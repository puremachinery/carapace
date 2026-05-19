//! Shared updater pipeline with mandatory Sigstore verification and transaction-based resume.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore_trust_root::{TrustedRoot, TufConfig};
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier, DEFAULT_CLOCK_SKEW_SECONDS};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use unicode_normalization::UnicodeNormalization;

#[cfg(test)]
use sigstore_trust_root::{
    PRODUCTION_TUF_ROOT, SIGSTORE_PRODUCTION_TRUSTED_ROOT, TRUSTED_ROOT_TARGET,
};
#[cfg(test)]
use std::sync::atomic::AtomicBool;

pub const EXPECTED_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const EXPECTED_IDENTITY_PREFIX: &str =
    "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/";

pub const DEFAULT_RESUME_MAX_ATTEMPTS: u32 = 3;
pub const NO_UPDATE_AVAILABLE_MESSAGE: &str = "no update available";
pub const LATEST_VERSION_UNKNOWN_MESSAGE: &str = "latest version not known; run update.check first";
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;
const UPDATE_TRANSACTION_FILENAME: &str = "transaction.json";
const UPDATE_LOCK_FILENAME: &str = "update.lock";
const UPDATE_ROLLBACK_FILENAME: &str = "rollback.json";
const UPDATE_STARTUP_HEALTH_FAILURE_FILENAME: &str = "startup_health_failure.json";

/// Cap for update marker JSON loads (`transaction.json`,
/// `rollback.json`, `startup_health_failure.json`). Legitimate
/// content is small JSON (URL, version, hash, phase, timestamps,
/// short error strings); 64 KiB is well above any realistic value
/// and well below an OOM risk. Without a cap a same-uid attacker
/// who plants a multi-GB file at any of these paths inside
/// `state_dir/updates/` OOMs the daemon at startup before tokio
/// reactor or audit log come up — every startup hits all three
/// loads, and there is no outer timeout. Mirrors the recovery-
/// rotation marker cap at `MATRIX_RECOVERY_ROTATION_MARKER_MAX_BYTES`
/// in `src/channels/matrix.rs`.
const UPDATE_MARKER_MAX_BYTES: u64 = 64 * 1024;
const RESUME_BACKOFF_SHORT_SECS: u64 = 5;
const RESUME_BACKOFF_MEDIUM_SECS: u64 = 15;
const RESUME_BACKOFF_LONG_SECS: u64 = 45;
pub(crate) const APPLY_CONFIRMATION_TTL_MS: u64 = 15 * 60 * 1000;

static UPDATE_OPERATION_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static UPDATE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static TEST_FORCE_COPY_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_FORCE_RESTORE_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_FORCE_ROLLBACK_MARKER_PERSIST_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_FORCE_ROLLBACK_MARKER_CLEAR_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_FORCE_ROLLBACK_MARKER_FSYNC_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_FORCE_ROLLBACK_BACKUP_REMOVE_FAIL: AtomicBool = AtomicBool::new(false);
/// Test-only opt-out for the canonical-binary-path verification in
/// rollback recovery. Real fixtures cannot write a marker whose
/// `binary_path` matches `std::env::current_exe()` (the nextest test
/// binary), so existing tests that exercise the marker lifecycle
/// against synthetic temp-dir paths set this to skip the verify.
/// Production code paths never flip this — guarded by `#[cfg(test)]`.
#[cfg(test)]
static TEST_SKIP_ROLLBACK_MARKER_PATH_VERIFY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub html_url: String,
    pub body: Option<String>,
    #[serde(default)]
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub applied: bool,
    pub sha256: String,
    pub binary_path: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateTransactionState {
    InProgress,
    Applied,
    Failed,
}

fn deserialize_update_transaction_state_forward_compat<'de, D>(
    deserializer: D,
) -> Result<UpdateTransactionState, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // COMPAT: an older binary reading a transaction.json written by a
    // newer daemon must NOT hard-error on parse. Hard-erroring here
    // turns `cara update install/resume` into a manual file-removal
    // chore for the operator on downgrade — exactly the scenario the
    // rollback mechanism exists to recover from. Mirrors the
    // `UpdatePhase` deserializer at `deserialize_update_phase_forward_compat`.
    // Unknown variants resolve to `Failed` so the in-flight transaction
    // is treated as a non-resumable failure (safest fail-closed
    // default; retryability gates additionally on `retryable`).
    let value = String::deserialize(deserializer)?;
    let state = match value.as_str() {
        "in_progress" => UpdateTransactionState::InProgress,
        "applied" => UpdateTransactionState::Applied,
        "failed" => UpdateTransactionState::Failed,
        _ => {
            tracing::warn!(
                update_transaction_state = %value,
                "update: unrecognized update transaction state wire name in transaction.json; \
                 treating as Failed for forward-compat (operator may need to clear \
                 transaction.json after downgrade)"
            );
            UpdateTransactionState::Failed
        }
    };
    Ok(state)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Created,
    Downloading,
    Downloaded,
    Verified,
    Applying,
    Applied,
    Failed,
}

impl UpdatePhase {
    pub const ALL: &'static [(UpdatePhase, &'static str)] = &[
        (UpdatePhase::Created, "created"),
        (UpdatePhase::Downloading, "downloading"),
        (UpdatePhase::Downloaded, "downloaded"),
        (UpdatePhase::Verified, "verified"),
        (UpdatePhase::Applying, "applying"),
        (UpdatePhase::Applied, "applied"),
        (UpdatePhase::Failed, "failed"),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            UpdatePhase::Created => "created",
            UpdatePhase::Downloading => "downloading",
            UpdatePhase::Downloaded => "downloaded",
            UpdatePhase::Verified => "verified",
            UpdatePhase::Applying => "applying",
            UpdatePhase::Applied => "applied",
            UpdatePhase::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateApplyConfirmation {
    /// Apply was requested directly by an operator-controlled command or API call.
    Explicit,
    /// Apply was requested by the updater's automatic resume/install path.
    Automatic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum UpdateRollbackStartupState {
    Pending,
    Started,
    RolledBack,
}

#[cfg(test)]
impl UpdateRollbackStartupState {
    const ALL: &'static [(UpdateRollbackStartupState, &'static str)] = &[
        (UpdateRollbackStartupState::Pending, "pending"),
        (UpdateRollbackStartupState::Started, "started"),
        (UpdateRollbackStartupState::RolledBack, "rolled_back"),
    ];

    fn as_str(self) -> &'static str {
        match self {
            UpdateRollbackStartupState::Pending => "pending",
            UpdateRollbackStartupState::Started => "started",
            UpdateRollbackStartupState::RolledBack => "rolled_back",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct UpdateRollbackMarker {
    pub binary_path: String,
    pub backup_path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_sha256: Option<String>,
    pub applied_at_ms: u64,
    #[serde(deserialize_with = "deserialize_update_rollback_startup_state_forward_compat")]
    pub startup_state: UpdateRollbackStartupState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolled_back_at_ms: Option<u64>,
    /// Forward-compat catch-all for fields a newer daemon may add;
    /// preserved on roundtrip so an older binary's rewrite during
    /// startup-resume doesn't silently drop them. Without this an
    /// operator who downgrades after an upgrade-incident has every
    /// newer-binary field stripped on the first older-binary
    /// startup-rollback rewrite — the post-downgrade incident-
    /// response evidence is lost. Mirrors the pattern in
    /// `ManagedPluginManifestEntry`.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Tolerate unknown `startup_state` wire values when an older binary
/// reads a rollback marker written by a newer daemon. The rollback
/// mechanism exists precisely to recover from a bad newer-binary
/// upgrade, so hard-erroring the marker parse defeats the purpose.
///
/// Unknown wire values fall back to `RolledBack` — the safest default:
/// it means "do not re-trigger rollback on this boot, trust that the
/// rollback either succeeded or is operator-attended", which matches
/// the failure-mode where this fallback could actually fire (newer
/// binary wrote a state the older binary doesn't recognize; treating
/// it as "still needs rollback" would re-run the restore_update_backup
/// logic, potentially clobbering the newer binary the operator just
/// installed). Surfaces a warn so the operator sees the drift.
///
/// Mirrors the audit-log `deserialize_update_phase_option_audit_compat`
/// pattern (audit.rs:474) and the `UpdateStartupHealthFailure.phase`
/// pattern (deserialize_update_phase_option_forward_compat below).
fn deserialize_update_rollback_startup_state_forward_compat<'de, D>(
    deserializer: D,
) -> Result<UpdateRollbackStartupState, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    match value.as_str() {
        "pending" => Ok(UpdateRollbackStartupState::Pending),
        "started" => Ok(UpdateRollbackStartupState::Started),
        "rolled_back" => Ok(UpdateRollbackStartupState::RolledBack),
        _ => {
            tracing::warn!(
                update_rollback_startup_state = %value,
                "update: unrecognized rollback startup_state wire name; falling back to rolled_back for forward-compat read"
            );
            Ok(UpdateRollbackStartupState::RolledBack)
        }
    }
}

macro_rules! define_update_startup_evidence_kind {
    ($($variant:ident => $wire:literal,)+) => {
        #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
        pub enum UpdateStartupEvidenceKind {
            $(
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl UpdateStartupEvidenceKind {
            pub const ALL: &'static [(UpdateStartupEvidenceKind, &'static str)] = &[
                $((UpdateStartupEvidenceKind::$variant, $wire),)+
            ];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(UpdateStartupEvidenceKind::$variant => $wire,)+
                }
            }
        }
    };
}

define_update_startup_evidence_kind! {
    UpdateHealthyMarkerFailed => "update_healthy_marker_failed",
    StartupRollbackCleanupFailed => "startup_rollback_cleanup_failed",
}

/// Tolerate unknown `event` wire values when an older binary reads a
/// startup-health-failure file written by a newer daemon. Without
/// this, `load_update_startup_health_failure` hard-errors with
/// `non_retryable` and blocks `mark_pending_update_healthy` /
/// `cara update install` resume on every boot — exactly the
/// downgrade-recovery scenario the rollback mechanism exists to
/// handle. Mirrors `deserialize_update_phase_forward_compat`
/// discipline: fall back to a conservative sentinel
/// (`UpdateHealthyMarkerFailed`, the more-conservative of the
/// current two variants since both treat the evidence as
/// "do not retry rollback") and surface a warn so the operator
/// sees the drift.
fn deserialize_update_startup_evidence_kind_forward_compat<'de, D>(
    deserializer: D,
) -> Result<UpdateStartupEvidenceKind, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    for (variant, wire) in UpdateStartupEvidenceKind::ALL {
        if *wire == value.as_str() {
            return Ok(*variant);
        }
    }
    tracing::warn!(
        evidence_kind = %value,
        "update: unrecognized startup-evidence kind wire name; falling back to \
         update_healthy_marker_failed (conservative default; operator may need to \
         clear the startup-health-failure evidence file after downgrade)"
    );
    Ok(UpdateStartupEvidenceKind::UpdateHealthyMarkerFailed)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStartupHealthFailure {
    #[serde(deserialize_with = "deserialize_update_startup_evidence_kind_forward_compat")]
    pub event: UpdateStartupEvidenceKind,
    pub failed_at_ms: u64,
    pub message: String,
    pub retryable: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_update_phase_option_forward_compat"
    )]
    pub phase: Option<UpdatePhase>,
}

fn deserialize_update_phase_option_forward_compat<'de, D>(
    deserializer: D,
) -> Result<Option<UpdatePhase>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    // The wire format is snake_case (matches the `#[serde(rename_all =
    // "snake_case")]` on UpdatePhase). An older binary reading evidence
    // written by a newer daemon — the precise scenario the rollback
    // mechanism exists to recover — must NOT hard-error parse. Treat
    // unknown variants as missing and warn.
    let phase = match value.as_str() {
        "created" => Some(UpdatePhase::Created),
        "downloading" => Some(UpdatePhase::Downloading),
        "downloaded" => Some(UpdatePhase::Downloaded),
        "verified" => Some(UpdatePhase::Verified),
        "applying" => Some(UpdatePhase::Applying),
        "applied" => Some(UpdatePhase::Applied),
        "failed" => Some(UpdatePhase::Failed),
        _ => {
            tracing::warn!(
                update_phase = %value,
                "update: unrecognized update phase wire name in startup health failure; treating as missing for forward-compat read"
            );
            None
        }
    };
    Ok(phase)
}

#[derive(Debug, Clone)]
pub enum UpdateHealthyMarkerError {
    Marker {
        error: UpdateError,
        evidence: Option<UpdateStartupHealthFailure>,
    },
    EvidenceCleanup(UpdateError),
}

impl UpdateHealthyMarkerError {
    pub fn update_error(&self) -> &UpdateError {
        match self {
            UpdateHealthyMarkerError::Marker { error, .. } => error,
            UpdateHealthyMarkerError::EvidenceCleanup(error) => error,
        }
    }

    pub fn failure_evidence_persisted(&self) -> bool {
        matches!(
            self,
            UpdateHealthyMarkerError::Marker {
                evidence: Some(_),
                ..
            }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTransaction {
    pub id: String,
    pub version: String,
    pub asset_name: String,
    #[serde(deserialize_with = "deserialize_update_transaction_state_forward_compat")]
    pub state: UpdateTransactionState,
    pub attempt: u32,
    pub max_attempts: u32,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub staged_path: Option<String>,
    pub bundle_path: Option<String>,
    pub sha256: Option<String>,
    pub last_error: Option<String>,
    #[serde(deserialize_with = "deserialize_update_phase_forward_compat")]
    pub phase: UpdatePhase,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_confirmed_until_ms: Option<u64>,
    /// Forward-compat catch-all for fields a newer daemon may add;
    /// preserved on roundtrip so an older binary that
    /// `load_update_transaction` -> mutate -> `persist_update_transaction`
    /// does not silently drop newer-binary fields (apply telemetry,
    /// retry counters, new metadata). Mirrors the pattern in
    /// `ManagedPluginManifestEntry` and `UpdateRollbackMarker`.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn deserialize_update_phase_forward_compat<'de, D>(deserializer: D) -> Result<UpdatePhase, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    // COMPAT: an older binary reading a transaction.json written by
    // a newer daemon must NOT hard-error on parse. The neighboring
    // `UpdateStartupHealthFailure.phase`, `UpdateRollbackMarker
    // .startup_state`, and the audit-log UpdatePhase field all
    // tolerate unknown variants via similar custom deserializers;
    // this field is the missing fourth corner. Without the
    // tolerance an older binary reading a newer transaction.json
    // (the precise scenario the rollback mechanism exists to
    // recover) breaks `cara update install` until the operator
    // manually deletes transaction.json. Unknown variants resolve
    // to `Failed` so the in-flight transaction is treated as a
    // non-resumable failure — the safest fail-closed default.
    let phase = match value.as_str() {
        "created" => UpdatePhase::Created,
        "downloading" => UpdatePhase::Downloading,
        "downloaded" => UpdatePhase::Downloaded,
        "verified" => UpdatePhase::Verified,
        "applying" => UpdatePhase::Applying,
        "applied" => UpdatePhase::Applied,
        "failed" => UpdatePhase::Failed,
        _ => {
            tracing::warn!(
                update_phase = %value,
                "update: unrecognized update phase wire name in transaction.json; \
                 treating as Failed for forward-compat (operator may need to clear \
                 transaction.json after downgrade)"
            );
            UpdatePhase::Failed
        }
    };
    Ok(phase)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationSummary {
    pub bundle_verified: bool,
    pub checksum_verified: bool,
    pub expected_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOutcome {
    pub version: String,
    pub staged_path: String,
    pub applied: bool,
    pub apply_result: Option<ApplyResult>,
    pub verification: VerificationSummary,
    pub transaction: Option<UpdateTransaction>,
    pub resumed: bool,
    pub attempt: u32,
}

#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub current_version: String,
    pub state_dir: PathBuf,
    pub requested_version: Option<String>,
    pub apply_update: bool,
    pub apply_confirmation: UpdateApplyConfirmation,
}

#[derive(Debug, Clone)]
pub struct UpdateError {
    pub phase: Option<UpdatePhase>,
    pub retryable: bool,
    pub code: Option<UpdateErrorCode>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateErrorCode {
    NoUpdateAvailable,
    LatestVersionUnknown,
}

impl UpdateError {
    fn retryable<M: Into<String>>(phase: Option<UpdatePhase>, message: M) -> Self {
        Self {
            phase,
            retryable: true,
            code: None,
            message: message.into(),
        }
    }

    fn non_retryable<M: Into<String>>(phase: Option<UpdatePhase>, message: M) -> Self {
        Self {
            phase,
            retryable: false,
            code: None,
            message: message.into(),
        }
    }

    fn non_retryable_with_code<M: Into<String>>(
        phase: Option<UpdatePhase>,
        code: UpdateErrorCode,
        message: M,
    ) -> Self {
        Self {
            phase,
            retryable: false,
            code: Some(code),
            message: message.into(),
        }
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.phase {
            Some(phase) => write!(f, "{phase:?}: {}", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for UpdateError {}

pub fn now_ms() -> u64 {
    crate::time::unix_now_ms_u64()
}

pub fn expected_asset_name() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = std::env::consts::ARCH;
    let ext = if std::env::consts::OS == "windows" {
        ".exe"
    } else {
        ""
    };
    format!("cara-{arch}-{os}{ext}")
}

pub fn expected_bundle_name(asset_name: &str) -> String {
    format!("{asset_name}.bundle")
}

pub fn expected_checksum_name() -> &'static str {
    "SHA256SUMS.txt"
}

pub fn tag_to_version(tag: &str) -> String {
    tag.strip_prefix('v').unwrap_or(tag).to_string()
}

pub fn version_to_tag(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

pub fn expected_identity_for_tag(tag: &str) -> String {
    format!("{EXPECTED_IDENTITY_PREFIX}{tag}")
}

pub fn release_api_url(version: Option<&str>) -> String {
    match version {
        Some(v) => format!(
            "https://api.github.com/repos/puremachinery/carapace/releases/tags/{}",
            version_to_tag(v)
        ),
        None => "https://api.github.com/repos/puremachinery/carapace/releases/latest".to_string(),
    }
}

pub fn update_transaction_path(state_dir: &Path) -> PathBuf {
    state_dir.join("updates").join(UPDATE_TRANSACTION_FILENAME)
}

fn update_lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join("updates").join(UPDATE_LOCK_FILENAME)
}

fn update_rollback_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("updates").join(UPDATE_ROLLBACK_FILENAME)
}

fn update_startup_health_failure_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("updates")
        .join(UPDATE_STARTUP_HEALTH_FAILURE_FILENAME)
}

fn ensure_update_state_dir_secure(
    state_dir: &Path,
    phase: Option<UpdatePhase>,
) -> Result<(), UpdateError> {
    fs::create_dir_all(state_dir).map_err(|err| {
        UpdateError::retryable(
            phase,
            format!(
                "failed to create update state dir '{}': {err}",
                state_dir.display()
            ),
        )
    })?;
    ensure_private_update_dir(state_dir, phase, "state_dir")?;
    let updates_dir = state_dir.join("updates");
    fs::create_dir_all(&updates_dir).map_err(|err| {
        UpdateError::retryable(
            phase,
            format!(
                "failed to create update transaction dir '{}': {err}",
                updates_dir.display()
            ),
        )
    })?;
    ensure_private_update_dir(&updates_dir, phase, "updates_dir")
}

#[cfg(unix)]
fn ensure_private_update_dir(
    path: &Path,
    phase: Option<UpdatePhase>,
    label: &str,
) -> Result<(), UpdateError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).map_err(|err| {
        UpdateError::retryable(
            phase,
            format!(
                "failed to inspect update {label} '{}': {err}",
                path.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(UpdateError::non_retryable(
            phase,
            format!(
                "update {label} '{}' must be a real directory, not a symlink or file",
                path.display()
            ),
        ));
    }
    // SAFETY: `libc::geteuid` is a pure libc syscall with no
    // preconditions and no pointer arguments.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(UpdateError::non_retryable(
            phase,
            format!(
                "update {label} '{}' is owned by uid {}, expected current uid {}",
                path.display(),
                metadata.uid(),
                euid
            ),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            UpdateError::non_retryable(
                phase,
                format!(
                    "failed to chmod update {label} '{}' to 0700: {err}",
                    path.display()
                ),
            )
        })?;
        let mode = fs::symlink_metadata(path)
            .map_err(|err| {
                UpdateError::retryable(
                    phase,
                    format!(
                        "failed to re-inspect update {label} '{}': {err}",
                        path.display()
                    ),
                )
            })?
            .mode();
        if mode & 0o077 != 0 {
            return Err(UpdateError::non_retryable(
                phase,
                format!(
                    "update {label} '{}' remains accessible to group/other after chmod",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_update_dir(
    path: &Path,
    phase: Option<UpdatePhase>,
    label: &str,
) -> Result<(), UpdateError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        UpdateError::retryable(
            phase,
            format!(
                "failed to inspect update {label} '{}': {err}",
                path.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(UpdateError::non_retryable(
            phase,
            format!(
                "update {label} '{}' must be a real directory, not a symlink or file",
                path.display()
            ),
        ));
    }
    Ok(())
}

struct UpdateOperationGuard {
    // Field drop order matters: Rust drops fields in declaration
    // order, and the OS `flock` MUST release BEFORE the in-process
    // mutex so a queued Task B cannot wake from the tokio mutex and
    // attempt `flock(LOCK_NB)` while Task A's still-live `_file_lock`
    // holds the kernel lock on a different fd (Linux flock(2) treats
    // FDs from the same process as independent locks, so the
    // not-yet-dropped fd would return EWOULDBLOCK and surface the
    // misleading "already held by another process" retryable error).
    _file_lock: crate::sessions::file_lock::FileLock,
    _process_guard: tokio::sync::MutexGuard<'static, ()>,
}

async fn acquire_update_operation_guard(
    state_dir: &Path,
) -> Result<UpdateOperationGuard, UpdateError> {
    let process_guard = UPDATE_OPERATION_LOCK.lock().await;
    ensure_update_state_dir_secure(state_dir, None)?;
    let lock_path = update_lock_path(state_dir);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            UpdateError::retryable(
                None,
                format!(
                    "failed to create update lock dir '{}': {err}",
                    parent.display()
                ),
            )
        })?;
    }

    let file_lock = match crate::sessions::file_lock::FileLock::try_acquire(&lock_path) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            return Err(UpdateError::retryable(
                None,
                format!(
                    "update transaction lock at '{}' is already held by another process",
                    lock_path.display()
                ),
            ));
        }
        Err(err) => {
            return Err(UpdateError::retryable(
                None,
                format!(
                    "failed to acquire update transaction lock at '{}': {err}",
                    lock_path.display()
                ),
            ));
        }
    };

    Ok(UpdateOperationGuard {
        _file_lock: file_lock,
        _process_guard: process_guard,
    })
}

fn update_staging_path(state_dir: &Path, version: &str) -> PathBuf {
    let safe_version = sanitize_version_for_path(version);
    state_dir
        .join("updates")
        .join(format!("cara-{safe_version}"))
}

fn update_bundle_path(state_dir: &Path, version: &str) -> PathBuf {
    let safe_version = sanitize_version_for_path(version);
    state_dir
        .join("updates")
        .join(format!("cara-{safe_version}.bundle"))
}

pub fn load_update_transaction(state_dir: &Path) -> Result<Option<UpdateTransaction>, UpdateError> {
    ensure_update_state_dir_secure(state_dir, None)?;
    let path = update_transaction_path(state_dir);
    // O_NOFOLLOW + O_NONBLOCK via the shared helper: a same-uid
    // attacker who plants a FIFO at transaction.json would otherwise
    // hang the daemon startup path (`load_update_transaction` runs
    // before any tokio timeout wrapper). The path.exists() probe is
    // gone — the helper returns Ok(None) for NotFound so missing-
    // file semantics are preserved without a separate path
    // resolution. Capped via UPDATE_MARKER_MAX_BYTES so the same
    // attacker substituting /dev/zero or a multi-GB regular file
    // also doesn't OOM the daemon (uncapped variant docstring warns
    // the caller MUST cap — same lesson the matrix recovery-marker
    // helper learned).
    let data =
        match crate::paths::read_to_vec_no_hang_no_follow_capped(&path, UPDATE_MARKER_MAX_BYTES) {
            Ok(Some(data)) => data,
            Ok(None) => return Ok(None),
            Err(err) => {
                return Err(UpdateError::retryable(
                    None,
                    format!(
                        "failed to read update transaction '{}': {err}",
                        path.display()
                    ),
                ));
            }
        };

    let transaction = serde_json::from_slice::<UpdateTransaction>(&data).map_err(|err| {
        UpdateError::non_retryable(
            None,
            format!(
                "failed to parse update transaction '{}': {err}",
                path.display()
            ),
        )
    })?;
    validate_update_transaction(state_dir, &transaction)?;
    Ok(Some(transaction))
}

pub fn persist_update_transaction(
    state_dir: &Path,
    transaction: &UpdateTransaction,
) -> Result<(), UpdateError> {
    ensure_update_state_dir_secure(state_dir, Some(transaction.phase))?;
    validate_update_transaction(state_dir, transaction)?;
    let path = update_transaction_path(state_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            UpdateError::retryable(
                Some(transaction.phase),
                format!("failed to create update dir '{}': {err}", parent.display()),
            )
        })?;
    }

    let tmp_path = unique_update_tmp_path(&path);

    let mut payload = serde_json::to_vec_pretty(transaction).map_err(|err| {
        UpdateError::non_retryable(
            Some(transaction.phase),
            format!("failed to serialize update transaction: {err}"),
        )
    })?;
    payload.push(b'\n');

    let result = (|| -> std::io::Result<()> {
        let mut file = create_update_tmp_file_owner_only(&tmp_path)?;
        file.write_all(&payload)?;
        file.sync_data()?;
        fs::rename(&tmp_path, &path)?;
        crate::paths::sync_parent_dir_blocking(&path)?;
        Ok(())
    })();

    if let Err(err) = result {
        remove_update_tmp_file_after_write_failure(&tmp_path, &err);
        return Err(UpdateError::retryable(
            Some(transaction.phase),
            format!(
                "failed to persist update transaction '{}': {err}",
                path.display()
            ),
        ));
    }

    Ok(())
}

fn validate_update_transaction(
    state_dir: &Path,
    transaction: &UpdateTransaction,
) -> Result<(), UpdateError> {
    if transaction.asset_name != expected_asset_name() {
        return Err(UpdateError::non_retryable(
            Some(transaction.phase),
            format!(
                "update transaction asset_name '{}' does not match this platform '{}'",
                transaction.asset_name,
                expected_asset_name()
            ),
        ));
    }
    if transaction.version.trim().is_empty() {
        return Err(UpdateError::non_retryable(
            Some(transaction.phase),
            "update transaction version cannot be empty",
        ));
    }
    if sanitize_version_for_path(&transaction.version) != transaction.version {
        return Err(UpdateError::non_retryable(
            Some(transaction.phase),
            format!(
                "update transaction version '{}' is not a safe path component",
                transaction.version
            ),
        ));
    }
    if transaction.max_attempts == 0 || transaction.attempt > transaction.max_attempts {
        return Err(UpdateError::non_retryable(
            Some(transaction.phase),
            format!(
                "update transaction attempt {}/{} is invalid",
                transaction.attempt, transaction.max_attempts
            ),
        ));
    }
    if transaction.updated_at_ms < transaction.started_at_ms {
        return Err(UpdateError::non_retryable(
            Some(transaction.phase),
            "update transaction updated_at_ms predates started_at_ms",
        ));
    }
    if let Some(path) = transaction.staged_path.as_deref() {
        validate_transaction_path(
            state_dir,
            &transaction.version,
            path,
            update_staging_path,
            "staged_path",
            transaction.phase,
        )?;
    }
    if let Some(path) = transaction.bundle_path.as_deref() {
        validate_transaction_path(
            state_dir,
            &transaction.version,
            path,
            update_bundle_path,
            "bundle_path",
            transaction.phase,
        )?;
    }
    if let Some(hash) = transaction.sha256.as_deref() {
        if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(UpdateError::non_retryable(
                Some(transaction.phase),
                "update transaction sha256 is not a 64-character hex digest",
            ));
        }
    }
    Ok(())
}

fn validate_transaction_path(
    state_dir: &Path,
    version: &str,
    stored: &str,
    expected: fn(&Path, &str) -> PathBuf,
    field: &str,
    phase: UpdatePhase,
) -> Result<(), UpdateError> {
    let stored_path = PathBuf::from(stored);
    let expected_path = expected(state_dir, version);
    if !update_paths_match(&stored_path, &expected_path) {
        return Err(UpdateError::non_retryable(
            Some(phase),
            format!(
                "update transaction {field} '{}' does not match expected '{}'",
                stored_path.display(),
                expected_path.display()
            ),
        ));
    }
    Ok(())
}

fn update_paths_match(left: &Path, right: &Path) -> bool {
    left == right
        || paths_refer_to_same_file(left, right)
        || canonical_update_paths_match(left, right)
        || normalized_update_path_strings_match(left, right)
}

fn canonical_update_paths_match(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn normalized_update_path_strings_match(left: &Path, right: &Path) -> bool {
    match (left.to_str(), right.to_str()) {
        (Some(left), Some(right)) => {
            let left: String = left.nfc().collect();
            let right: String = right.nfc().collect();
            left == right
        }
        _ => false,
    }
}

fn create_update_tmp_file_owner_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // O_NOFOLLOW defense-in-depth — see `paths::create_atomic_tmp_owner_only`
        // for the threat model. `create_new`'s O_EXCL refuses a planted
        // symlink today; O_NOFOLLOW guards against a future refactor.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

fn unique_update_tmp_path(path: &Path) -> PathBuf {
    let counter = UPDATE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("update");
    let tmp_name = format!(
        ".{name}.{}.{}.{}.tmp",
        std::process::id(),
        counter,
        uuid::Uuid::new_v4()
    );
    path.parent()
        .map(|parent| parent.join(&tmp_name))
        .unwrap_or_else(|| PathBuf::from(tmp_name))
}

fn remove_update_tmp_file_after_write_failure(path: &Path, err: &std::io::Error) {
    if err.kind() != std::io::ErrorKind::AlreadyExists {
        let _ = fs::remove_file(path);
    }
}

pub fn clear_update_transaction(state_dir: &Path) -> Result<(), UpdateError> {
    ensure_update_state_dir_secure(state_dir, None)?;
    let path = update_transaction_path(state_dir);
    match fs::remove_file(&path) {
        Ok(()) => crate::paths::sync_parent_dir_blocking(&path).map_err(|err| {
            UpdateError::retryable(
                None,
                format!(
                    "failed to fsync update transaction removal '{}': {err}",
                    path.display()
                ),
            )
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            crate::paths::sync_parent_dir_blocking(&path).map_err(|err| {
                UpdateError::retryable(
                    None,
                    format!(
                        "failed to fsync update rollback marker parent after missing marker '{}': {err}",
                        path.display()
                    ),
                )
            })
        }
        Err(err) => Err(UpdateError::retryable(
            None,
            format!(
                "failed to remove update transaction '{}': {err}",
                path.display()
            ),
        )),
    }
}

fn persist_update_rollback_marker(
    state_dir: &Path,
    marker: &UpdateRollbackMarker,
) -> Result<(), UpdateError> {
    ensure_update_state_dir_secure(state_dir, Some(UpdatePhase::Applied))?;
    if marker.startup_state != UpdateRollbackStartupState::RolledBack {
        validate_update_rollback_backup_path(Path::new(&marker.backup_path))?;
    }
    let path = update_rollback_marker_path(state_dir);
    let tmp_path = unique_update_tmp_path(&path);
    let mut payload = serde_json::to_vec_pretty(marker).map_err(|err| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!("failed to serialize update rollback marker: {err}"),
        )
    })?;
    payload.push(b'\n');
    let result = (|| -> std::io::Result<()> {
        #[cfg(test)]
        if TEST_FORCE_ROLLBACK_MARKER_PERSIST_FAIL.swap(false, Ordering::SeqCst) {
            return Err(std::io::Error::other(
                "forced rollback marker persist failure",
            ));
        }
        let mut file = create_update_tmp_file_owner_only(&tmp_path)?;
        file.write_all(&payload)?;
        file.sync_data()?;
        fs::rename(&tmp_path, &path)?;
        crate::paths::sync_parent_dir_blocking(&path)?;
        Ok(())
    })();
    if let Err(err) = result {
        remove_update_tmp_file_after_write_failure(&tmp_path, &err);
        return Err(UpdateError::retryable(
            Some(UpdatePhase::Applied),
            format!(
                "failed to persist update rollback marker '{}': {err}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validate_update_rollback_backup_path(backup_path: &Path) -> Result<(), UpdateError> {
    if no_follow_regular_file_metadata(backup_path).is_ok() {
        return Ok(());
    }
    Err(UpdateError::non_retryable(
        Some(UpdatePhase::Applied),
        format!(
            "update rollback backup path '{}' is not a no-follow regular file",
            backup_path.display()
        ),
    ))
}

fn load_update_rollback_marker(
    state_dir: &Path,
) -> Result<Option<UpdateRollbackMarker>, UpdateError> {
    ensure_update_state_dir_secure(state_dir, None)?;
    let path = update_rollback_marker_path(state_dir);
    // O_NOFOLLOW + O_NONBLOCK + UPDATE_MARKER_MAX_BYTES cap: see the
    // equivalent comment at load_update_transaction. Rollback
    // marker load also runs on every daemon startup without an
    // outer timeout.
    let data =
        match crate::paths::read_to_vec_no_hang_no_follow_capped(&path, UPDATE_MARKER_MAX_BYTES) {
            Ok(Some(data)) => data,
            Ok(None) => return Ok(None),
            Err(err) => {
                return Err(UpdateError::retryable(
                    None,
                    format!(
                        "failed to read update rollback marker '{}': {err}",
                        path.display()
                    ),
                ));
            }
        };
    serde_json::from_slice::<UpdateRollbackMarker>(&data)
        .map(Some)
        .map_err(|err| {
            UpdateError::non_retryable(
                None,
                format!(
                    "failed to parse update rollback marker '{}': {err}",
                    path.display()
                ),
            )
        })
}

fn persist_update_startup_health_failure(
    state_dir: &Path,
    error: &UpdateError,
) -> Result<UpdateStartupHealthFailure, UpdateError> {
    persist_update_startup_health_failure_for_kind(
        state_dir,
        error,
        UpdateStartupEvidenceKind::UpdateHealthyMarkerFailed,
    )
}

fn persist_update_startup_health_failure_for_kind(
    state_dir: &Path,
    error: &UpdateError,
    event: UpdateStartupEvidenceKind,
) -> Result<UpdateStartupHealthFailure, UpdateError> {
    ensure_update_state_dir_secure(state_dir, error.phase)?;
    let failure = UpdateStartupHealthFailure {
        event,
        failed_at_ms: now_ms(),
        message: error.message.clone(),
        retryable: error.retryable,
        phase: error.phase,
    };
    let path = update_startup_health_failure_path(state_dir);
    let tmp_path = unique_update_tmp_path(&path);
    let mut payload = serde_json::to_vec_pretty(&failure).map_err(|err| {
        UpdateError::non_retryable(
            error.phase,
            format!("failed to serialize update startup health failure: {err}"),
        )
    })?;
    payload.push(b'\n');
    let result = (|| -> std::io::Result<()> {
        let mut file = create_update_tmp_file_owner_only(&tmp_path)?;
        file.write_all(&payload)?;
        file.sync_data()?;
        fs::rename(&tmp_path, &path)?;
        crate::paths::sync_parent_dir_blocking(&path)?;
        Ok(())
    })();
    if let Err(err) = result {
        remove_update_tmp_file_after_write_failure(&tmp_path, &err);
        return Err(UpdateError::retryable(
            error.phase,
            format!(
                "failed to persist update startup health failure '{}': {err}",
                path.display()
            ),
        ));
    }
    Ok(failure)
}

pub fn load_update_startup_health_failure(
    state_dir: &Path,
) -> Result<Option<UpdateStartupHealthFailure>, UpdateError> {
    ensure_update_state_dir_secure(state_dir, None)?;
    let path = update_startup_health_failure_path(state_dir);
    // O_NOFOLLOW + O_NONBLOCK + UPDATE_MARKER_MAX_BYTES cap: see
    // the equivalent comment at load_update_transaction.
    let data =
        match crate::paths::read_to_vec_no_hang_no_follow_capped(&path, UPDATE_MARKER_MAX_BYTES) {
            Ok(Some(data)) => data,
            Ok(None) => return Ok(None),
            Err(err) => {
                return Err(UpdateError::retryable(
                    None,
                    format!(
                        "failed to read update startup health failure '{}': {err}",
                        path.display()
                    ),
                ));
            }
        };
    serde_json::from_slice::<UpdateStartupHealthFailure>(&data)
        .map(Some)
        .map_err(|err| {
            UpdateError::non_retryable(
                None,
                format!(
                    "failed to parse update startup health failure '{}': {err}",
                    path.display()
                ),
            )
        })
}

fn clear_update_startup_health_failure(state_dir: &Path) -> Result<(), UpdateError> {
    ensure_update_state_dir_secure(state_dir, None)?;
    let path = update_startup_health_failure_path(state_dir);
    match fs::remove_file(&path) {
        Ok(()) => crate::paths::sync_parent_dir_blocking(&path).map_err(|err| {
            UpdateError::retryable(
                None,
                format!(
                    "failed to fsync update startup health failure removal '{}': {err}",
                    path.display()
                ),
            )
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(UpdateError::retryable(
            None,
            format!(
                "failed to remove update startup health failure '{}': {err}",
                path.display()
            ),
        )),
    }
}

fn clear_update_rollback_marker(state_dir: &Path) -> Result<(), UpdateError> {
    ensure_update_state_dir_secure(state_dir, None)?;
    let path = update_rollback_marker_path(state_dir);
    match fs::remove_file(&path) {
        Ok(()) => {
            #[cfg(test)]
            if TEST_FORCE_ROLLBACK_MARKER_CLEAR_FAIL.swap(false, Ordering::SeqCst) {
                return Err(UpdateError::retryable(
                    None,
                    "forced rollback marker clear failure",
                ));
            }
            // Post-unlink fsync is best-effort. Once `remove_file`
            // returned Ok, the in-memory dirent for the marker is
            // gone — retrying this function would observe NotFound
            // and short-circuit to Ok without re-attempting the
            // fsync, so propagating a "retryable" error here is
            // misleading: it convinces the caller a retry could
            // succeed when in fact no retry path can re-fsync the
            // already-completed unlink. Worse, the outer
            // `mark_pending_update_healthy` would persist
            // failure-evidence, and a power loss before the dirent
            // change durably commits could let the next boot see
            // the marker still on disk and trigger a false-positive
            // rollback that undoes the healthy update.
            let fsync_result: std::io::Result<()> = {
                #[cfg(test)]
                if TEST_FORCE_ROLLBACK_MARKER_FSYNC_FAIL.swap(false, Ordering::SeqCst) {
                    Err(std::io::Error::other(
                        "forced rollback marker fsync failure",
                    ))
                } else {
                    crate::paths::sync_parent_dir_blocking(&path)
                }
                #[cfg(not(test))]
                crate::paths::sync_parent_dir_blocking(&path)
            };
            if let Err(err) = fsync_result {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to fsync parent dir after removing update rollback marker; \
                     marker is gone from in-memory state but dirent durability is degraded — \
                     a power loss before the kernel flushes this change could let the next \
                     boot see the marker again"
                );
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(UpdateError::retryable(
            None,
            format!(
                "failed to remove update rollback marker '{}': {err}",
                path.display()
            ),
        )),
    }
}

pub fn transaction_resume_pending(tx: &UpdateTransaction) -> bool {
    match tx.state {
        UpdateTransactionState::InProgress => true,
        UpdateTransactionState::Failed => tx.retryable && tx.attempt < tx.max_attempts,
        UpdateTransactionState::Applied => false,
    }
}

fn apply_confirmation_deadline(now: u64) -> u64 {
    now.saturating_add(APPLY_CONFIRMATION_TTL_MS)
}

fn refresh_apply_confirmation(tx: &mut UpdateTransaction) {
    tx.apply_confirmed_until_ms = Some(apply_confirmation_deadline(now_ms()));
}

fn apply_confirmation_is_fresh(tx: &UpdateTransaction, now: u64) -> bool {
    tx.apply_confirmed_until_ms
        .is_some_and(|deadline| deadline >= now)
}

fn stale_apply_confirmation_error(tx: &UpdateTransaction) -> UpdateError {
    UpdateError::non_retryable(
        Some(tx.phase),
        format!(
            "stale update transaction {} requires fresh operator confirmation before applying; rerun `cara update` to resume intentionally",
            tx.id
        ),
    )
}

pub fn compute_sha256(path: &Path) -> Result<String, UpdateError> {
    let mut file = File::open(path).map_err(|e| {
        UpdateError::retryable(
            None,
            format!("failed to open file '{}' for hashing: {e}", path.display()),
        )
    })?;
    hash_open_file(&mut file, path)
}

/// `O_NOFOLLOW` companion to `compute_sha256`. Refuses to traverse a
/// symlink at the supplied path AND verifies the opened fd is a
/// regular file. Used at the rollback-backup hash-and-persist site
/// and at recovery-time current-binary hash so that an attacker who
/// can momentarily plant a symlink in the binary's parent directory
/// cannot trick the marker into recording an attacker-chosen
/// `backup_sha256` (or persuade the recovery probe to believe the
/// running binary's hash matches a foreign target).
pub fn compute_sha256_no_follow(path: &Path) -> Result<String, UpdateError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW + O_NONBLOCK: the post-open is_file() check
        // below refuses FIFO dirents but only AFTER open(2) returns.
        // The update pipeline (daemon-side and CLI-side) runs without
        // an outer timeout; a same-uid attacker (compromised plugin /
        // tool-call escape) who plants a FIFO at the staged-binary
        // or current_path otherwise hangs the update apply phase
        // indefinitely. Regular files ignore O_NONBLOCK, so the
        // happy path is unchanged.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|e| {
        UpdateError::retryable(
            None,
            format!(
                "failed to open file '{}' for no-follow hashing: {e}",
                path.display()
            ),
        )
    })?;
    let metadata = file.metadata().map_err(|e| {
        UpdateError::retryable(
            None,
            format!(
                "failed to read metadata of '{}' for no-follow hashing: {e}",
                path.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || update_metadata_is_reparse_point(&metadata) {
        return Err(UpdateError::non_retryable(
            None,
            format!(
                "refusing to hash '{}': path is a symlink or reparse point",
                path.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err(UpdateError::non_retryable(
            None,
            format!(
                "refusing to hash '{}': path is not a regular file",
                path.display()
            ),
        ));
    }
    hash_open_file(&mut file, path)
}

fn hash_open_file(file: &mut File, path: &Path) -> Result<String, UpdateError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer).map_err(|e| {
            UpdateError::retryable(
                None,
                format!("failed to read file '{}' for hashing: {e}", path.display()),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(sha256_digest_bytes(data).as_bytes())
}

/// Verify a staged artifact hash against one checksum entry line from SHA256SUMS.
pub fn verify_checksum(actual_hash: &str, checksum_line: &str) -> Result<(), UpdateError> {
    let expected = checksum_line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();

    if expected.is_empty() {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Verified),
            "checksum file is empty or malformed",
        ));
    }

    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Verified),
            format!("checksum file does not contain a valid SHA-256 hash: '{expected}'"),
        ));
    }

    if actual_hash != expected {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Verified),
            format!("SHA-256 mismatch: expected {expected}, got {actual_hash}"),
        ));
    }

    Ok(())
}

pub fn apply_staged_update(
    staged_path: &str,
    expected_hash: Option<&str>,
) -> Result<ApplyResult, UpdateError> {
    let staged = Path::new(staged_path);
    let current_exe = std::env::current_exe().map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("failed to determine current binary path: {e}"),
        )
    })?;
    let current_path = current_exe.canonicalize().map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("failed to canonicalize current binary path: {e}"),
        )
    })?;
    apply_staged_update_at_paths(staged, &current_path, expected_hash)
}

fn backup_path_for_binary(current_path: &Path) -> PathBuf {
    let mut os = current_path.as_os_str().to_os_string();
    os.push(".bak");
    PathBuf::from(os)
}

/// Verify the rollback marker's binary_path / backup_path pair
/// against the current executable's canonical path.
///
/// Returns `Err(UpdateError::non_retryable(..))` if either path
/// does not match the canonical mapping. Used by the
/// recovery-on-startup paths (`restore_update_backup`,
/// `remove_update_rollback_backup_after_healthy`) to refuse a
/// marker whose paths were tampered with — a same-uid attacker
/// with write access to `state_dir/update-rollback.json` would
/// otherwise be able to redirect the restore or the post-success
/// cleanup to attacker-chosen paths.
fn verify_rollback_marker_paths(
    marker_binary_path: &Path,
    marker_backup_path: &Path,
) -> Result<(), UpdateError> {
    #[cfg(test)]
    {
        if TEST_SKIP_ROLLBACK_MARKER_PATH_VERIFY.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
    let current_exe = std::env::current_exe().map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!("failed to determine current binary path for rollback verify: {e}"),
        )
    })?;
    let canonical_current = current_exe.canonicalize().map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!("failed to canonicalize current binary path for rollback verify: {e}"),
        )
    })?;
    // Canonicalize the marker's binary_path too so symlink-vs-real
    // discrepancies don't false-fail (e.g., installer drops a
    // symlink at /usr/local/bin/cara and the marker records the
    // real path).
    let canonical_marker_binary = match Path::new(marker_binary_path).canonicalize() {
        Ok(path) => path,
        Err(e) => {
            return Err(UpdateError::non_retryable(
                Some(UpdatePhase::Applied),
                format!(
                    "rollback marker binary_path canonicalize failed: {e} (refusing tampered marker)"
                ),
            ));
        }
    };
    if canonical_marker_binary != canonical_current {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            "rollback marker binary_path does not match current executable; refusing tampered marker (canonical-mismatch)".to_string(),
        ));
    }
    let expected_backup = backup_path_for_binary(&canonical_current);
    // Compare via canonicalize-if-present so a symlink at the
    // expected backup site doesn't shadow the real path. Backup may
    // not exist (it's the restore source — if missing, marker is
    // stale or already-consumed); in that case compare the recorded
    // marker path against the expected literal path.
    let marker_backup_path_buf = PathBuf::from(marker_backup_path);
    let matches = match (
        marker_backup_path_buf.canonicalize(),
        expected_backup.canonicalize(),
    ) {
        (Ok(a), Ok(b)) => a == b,
        // Backup file not present yet (or removed): compare the
        // literal marker string against the canonical expected
        // path. This is the post-cleanup case.
        _ => marker_backup_path_buf == expected_backup,
    };
    if !matches {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            "rollback marker backup_path does not match canonical mapping; refusing tampered marker".to_string(),
        ));
    }
    Ok(())
}

/// Open the staged binary with `O_NOFOLLOW` (where supported) and
/// verify the held fd is a regular file. The returned `File` is the
/// SOLE handle used through the apply path — see
/// `apply_staged_update_at_paths` for the threat-model commentary.
fn open_staged_for_apply_no_follow(staged: &Path) -> Result<File, UpdateError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW + O_NONBLOCK: see compute_sha256_no_follow's
        // companion comment. The staged binary is on the apply
        // hot-path with no outer timeout, so a planted FIFO at
        // `state_dir/updates/staged-<id>` would hang apply forever.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(staged).map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!(
                "failed to open staged binary '{}' for no-follow apply: {e}",
                staged.display()
            ),
        )
    })?;
    let metadata = file.metadata().map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!(
                "failed to read metadata of staged binary '{}': {e}",
                staged.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || update_metadata_is_reparse_point(&metadata) {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!(
                "refusing to apply '{}': path is a symlink or reparse point",
                staged.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!(
                "refusing to apply '{}': path is not a regular file",
                staged.display()
            ),
        ));
    }
    Ok(file)
}

/// Copy the contents of an already-open staged-binary fd to
/// `current_path`. The destination is opened with `create_new` so a
/// same-uid attacker cannot pre-plant `current_path` (the rename
/// already removed the daemon's prior binary; the dirent is absent at
/// the moment of this call). Final mode + sync_all + parent-dir fsync
/// are handled by the caller in `apply_staged_update_at_paths`.
fn copy_staged_fd_to_current_path(
    staged_file: &mut File,
    current_path: &Path,
) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW defense-in-depth — the rename has already cleared
        // current_path so an attacker would need to win the race with
        // O_EXCL; the second-line guard refuses a planted symlink even
        // if some future refactor weakens create_new.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut dest = options.open(current_path)?;
    std::io::copy(staged_file, &mut dest)?;
    Ok(())
}

fn apply_staged_update_at_paths(
    staged: &Path,
    current_path: &Path,
    expected_hash: Option<&str>,
) -> Result<ApplyResult, UpdateError> {
    // Open the staged binary ONCE with O_NOFOLLOW + regular-file check
    // and reuse the same fd for size, hash, copy AND content-binding.
    // The previous `fs::metadata(staged)` + `compute_sha256(staged)` +
    // `fs::copy(staged, ...)` sequence re-resolved the path three
    // times, giving a same-uid attacker who can briefly plant a
    // symlink in `state_dir/updates/` an arbitrary-binary-substitute
    // window. Batch 59 closed the within-apply TOCTOU; Batch 71 closes
    // the verify→apply TOCTOU by requiring callers to thread the
    // sigstore-verified `expected_hash` into this function so the
    // held-fd hash is checked BEFORE any rename/copy. Pass `None`
    // only from contexts that have no expected hash (notably the
    // legacy public entry point retained for backward compatibility).
    let mut staged_file = open_staged_for_apply_no_follow(staged)?;
    let staged_len = staged_file
        .metadata()
        .map_err(|e| {
            UpdateError::non_retryable(
                Some(UpdatePhase::Applying),
                format!(
                    "failed to read metadata of staged binary '{}': {e}",
                    staged.display()
                ),
            )
        })?
        .len();
    if staged_len == 0 {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("staged binary at '{}' is empty", staged.display()),
        ));
    }

    let sha256 = hash_open_file(&mut staged_file, staged)?;
    // Bind the apply to the sigstore-verified expected hash. Without
    // this check, a same-uid attacker who swaps the staged dirent
    // between the prior verify pass and this apply can have the
    // wrong bytes copied to `current_path` even though our held fd
    // is the post-swap file. The hash binds the bytes-about-to-be-
    // applied to the hash the verify path actually checked.
    if let Some(expected) = expected_hash {
        if sha256 != expected {
            return Err(UpdateError::non_retryable(
                Some(UpdatePhase::Applying),
                format!(
                    "staged binary at '{}' has hash {} but expected {} \
                     (staged dirent changed between verify and apply)",
                    staged.display(),
                    sha256,
                    expected
                ),
            ));
        }
    }
    let binary_path = current_path.to_string_lossy().into_owned();

    // Reset for the upcoming `io::copy` pass over the same fd.
    use std::io::Seek;
    staged_file.seek(std::io::SeekFrom::Start(0)).map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!(
                "failed to rewind staged binary '{}' before apply: {e}",
                staged.display()
            ),
        )
    })?;

    #[cfg(windows)]
    {
        // The Windows code path doesn't use the held fd (it uses
        // MoveFileExW shenanigans). Drop the fd so the file isn't
        // pinned during the Windows apply.
        drop(staged_file);
        return apply_staged_update_windows(staged, sha256, binary_path);
    }

    let backup_path = backup_path_for_binary(current_path);

    fs::rename(current_path, &backup_path).map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!(
                "failed to rename current binary to '{}': {e}",
                backup_path.display()
            ),
        )
    })?;
    // Durably commit the rename's dirent change (current_path is now
    // absent; backup_path is present) before writing the new binary.
    // Without this, a power loss between rename and copy can leave
    // the on-disk view with both entries missing or both
    // half-present, making post-crash recovery non-deterministic.
    if let Err(err) = crate::paths::sync_parent_dir_blocking(current_path) {
        tracing::warn!(
            path = %current_path.display(),
            error = %err,
            "failed to sync parent directory after rename of current binary to backup; \
             update rollback durability degraded"
        );
    }

    let copy_result: Result<(), std::io::Error> = {
        #[cfg(test)]
        {
            if TEST_FORCE_COPY_FAIL.swap(false, Ordering::SeqCst) {
                Err(std::io::Error::other("forced copy failure"))
            } else {
                copy_staged_fd_to_current_path(&mut staged_file, current_path)
            }
        }
        #[cfg(not(test))]
        {
            copy_staged_fd_to_current_path(&mut staged_file, current_path)
        }
    };

    if let Err(copy_err) = copy_result {
        #[cfg(test)]
        if TEST_FORCE_RESTORE_FAIL.swap(false, Ordering::SeqCst) {
            let _ = fs::remove_file(&backup_path);
        }
        if let Err(restore_err) = fs::rename(&backup_path, current_path) {
            return Err(UpdateError::non_retryable(
                Some(UpdatePhase::Applying),
                format!(
                    "CRITICAL: copy failed ({copy_err}) AND restore failed ({restore_err}). Backup path (if present): {}",
                    backup_path.display()
                ),
            ));
        }
        // Fsync the restore so the rolled-back current_path dirent
        // survives a follow-on power loss; otherwise the caller sees
        // a clean failure but the on-disk view is half-restored.
        if let Err(err) = crate::paths::sync_parent_dir_blocking(current_path) {
            tracing::warn!(
                path = %current_path.display(),
                error = %err,
                "failed to sync parent directory after restoring backup over current_path; \
                 the in-memory view reports rollback but disk durability is degraded"
            );
        }
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("failed to copy staged binary to current path: {copy_err}"),
        ));
    }

    // Set executable mode BEFORE the final file-level sync_all. POSIX
    // fsync on a directory commits only the directory's own data
    // (dirent table + dir inode), NOT the inode contents of files
    // within it. So a chmod followed only by a parent-dir fsync would
    // leave the mode change unflushed: a power loss before the kernel
    // flushed the inode could leave the new binary on disk and
    // reachable through the dirent but without the executable bit set,
    // preventing `cara` from running at next boot. The pre-fix ordering
    // was chmod-after-sync_all and only parent-dir fsync afterward.
    // Move the chmod before the file's sync_all so the mode is part of
    // the inode metadata committed by sync_all.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        if let Err(err) = fs::set_permissions(current_path, perms) {
            tracing::warn!(
                path = %current_path.display(),
                error = %err,
                "failed to set executable permissions on updated binary"
            );
        }
    }

    // Sync the freshly-copied binary's data + inode metadata (incl. the
    // chmod above) before declaring success so a power loss does not
    // leave the new dirent pointing at a zero-byte or partially-written
    // inode, nor a file with the wrong mode bits.
    match fs::OpenOptions::new().read(true).open(current_path) {
        Ok(file) => {
            if let Err(err) = file.sync_all() {
                tracing::warn!(
                    path = %current_path.display(),
                    error = %err,
                    "failed to sync_all updated binary; data durability degraded"
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                path = %current_path.display(),
                error = %err,
                "failed to reopen updated binary for sync_all; data durability degraded"
            );
        }
    }

    // Final parent-dir fsync to durably commit the new current_path
    // dirent (created by `fs::copy`). Without this, the caller proceeds
    // to marker persist (which fsyncs state_dir, NOT the binary's
    // parent) and a power loss between this return and the marker
    // landing can lose the new binary's dirent — leaving the next
    // boot with neither current_path nor the .bak.
    if let Err(err) = crate::paths::sync_parent_dir_blocking(current_path) {
        tracing::warn!(
            path = %current_path.display(),
            error = %err,
            "failed to sync parent directory after writing updated binary; \
             dirent durability degraded"
        );
    }

    Ok(ApplyResult {
        applied: true,
        sha256,
        binary_path,
    })
}

#[cfg(windows)]
fn apply_staged_update_windows(
    staged: &Path,
    sha256: String,
    binary_path: String,
) -> Result<ApplyResult, UpdateError> {
    self_replace::self_replace(staged).map_err(|err| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("failed to replace running binary on windows: {err}"),
        )
    })?;

    Ok(ApplyResult {
        applied: true,
        sha256,
        binary_path,
    })
}

pub(crate) fn cleanup_startup_update_state(state_dir: &Path) {
    let rollback_state = match begin_pending_update_startup(state_dir) {
        Ok(protected) => Some(protected),
        Err(err) => {
            tracing::warn!(
                phase = ?err.phase,
                retryable = err.retryable,
                error = %err.message,
                "failed to process pending update rollback marker during startup cleanup; preserving sibling rollback backups"
            );
            // Persist durable evidence so an operator inspecting the
            // state dir after a daemon restart can SEE that the
            // startup-side rollback machinery failed. Prior code only
            // emitted a `tracing::warn!`, which is volatile — if the
            // daemon's tracing sink is misconfigured or the process
            // crashed mid-cleanup, the operator had no on-disk
            // breadcrumb that the rollback path even ran. Demote
            // failures of THIS persistence to `tracing::error!` only;
            // we cannot recursively re-fail the cleanup path.
            match persist_update_startup_health_failure_for_kind(
                state_dir,
                &err,
                UpdateStartupEvidenceKind::StartupRollbackCleanupFailed,
            ) {
                Ok(_) => {}
                Err(persist_err) => {
                    tracing::error!(
                        phase = ?persist_err.phase,
                        error = %persist_err.message,
                        "failed to persist startup rollback cleanup evidence; rollback failure is now only in volatile tracing logs"
                    );
                }
            }
            None
        }
    };
    if let Some(protected_backup) = rollback_state {
        cleanup_bak_files_near_exe(state_dir, protected_backup.as_deref());
    }
    cleanup_stale_staged_updates(state_dir);
}

pub(crate) fn cleanup_old_binaries(state_dir: &Path) {
    cleanup_stale_staged_updates(state_dir);
}

fn persist_recoverable_rollback_marker_for_apply_result(
    state_dir: &Path,
    apply_result: &ApplyResult,
) -> Result<(), UpdateError> {
    let backup_path = backup_path_for_binary(Path::new(&apply_result.binary_path));
    if !backup_path.exists() {
        tracing::warn!(
            binary_path = %apply_result.binary_path,
            backup_path = %backup_path.display(),
            "update applied without a recoverable rollback backup; rollback marker not persisted"
        );
        return Ok(());
    }
    // Hash the backup with `O_NOFOLLOW` so an attacker who can
    // momentarily plant a symlink at `backup_path` between
    // `validate_update_rollback_backup_path` (which uses
    // `symlink_metadata`) and this hash cannot persuade the marker
    // to record an attacker-chosen `backup_sha256` — e.g., the
    // staged new binary's own hash so a future recovery probe
    // mistakes "current binary == backup" for a completed rollback.
    let backup_sha256 = compute_sha256_no_follow(&backup_path)?;
    persist_update_rollback_marker(
        state_dir,
        &UpdateRollbackMarker {
            binary_path: apply_result.binary_path.clone(),
            backup_path: backup_path.to_string_lossy().into_owned(),
            sha256: apply_result.sha256.clone(),
            backup_sha256: Some(backup_sha256),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Pending,
            started_at_ms: None,
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        },
    )
}

fn persist_recoverable_rollback_marker_after_apply(
    state_dir: &Path,
    apply_result: &ApplyResult,
) -> Result<(), UpdateError> {
    persist_recoverable_rollback_marker_for_apply_result(state_dir, apply_result).map_err(|err| {
        let backup_path = backup_path_for_binary(Path::new(&apply_result.binary_path));
        UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!(
                "{}; update applied but rollback safety marker was not persisted, so backup '{}' may be orphaned and removed by startup cleanup",
                err.message,
                backup_path.display()
            ),
        )
    })
}

/// Mark an applied update healthy after the new process has reached startup.
///
/// This remains public because the binary crate calls through the library
/// boundary after TLS/non-TLS server startup completes.
pub fn mark_pending_update_healthy(state_dir: &Path) -> Result<(), UpdateHealthyMarkerError> {
    match mark_pending_update_healthy_inner(state_dir) {
        Ok(true | false) => clear_update_startup_health_failure(state_dir).map_err(|error| {
            // Audit DURABLY: the rollback marker has already been
            // cleared and the backup file removed before this branch
            // runs (the irreversible operator-visible change). An
            // `audit::audit` (Enqueued) that later drops would leave
            // the operator with a state-dir that looks "healthy +
            // marker cleared" but no forensic record that the
            // health-failure evidence cleanup itself failed. Same
            // class as Batch 80.
            if let Err(audit_err) = crate::logging::audit::audit_durable_for_state_dir(
                state_dir.to_path_buf(),
                crate::logging::audit::AuditEvent::UpdateHealthyEvidenceCleanupFailed {
                    phase: error.phase,
                    retryable: error.retryable,
                },
            ) {
                tracing::error!(
                    audit_event = "update_healthy_evidence_cleanup_failed",
                    error = %audit_err,
                    "failed to durably audit healthy-evidence cleanup failure; \
                     operator-visible forensic evidence is incomplete"
                );
            }
            UpdateHealthyMarkerError::EvidenceCleanup(error)
        }),
        Err(err) => {
            let evidence = match persist_update_startup_health_failure(state_dir, &err) {
                Ok(failure) => {
                    tracing::error!(
                        audit_event = %failure.event.as_str(),
                        phase = ?failure.phase,
                        retryable = failure.retryable,
                        error = %failure.message,
                        "update healthy marker failure recorded for update.status"
                    );
                    Some(failure)
                }
                Err(evidence_err) => {
                    tracing::error!(
                        audit_event = "update_healthy_marker_failed",
                        phase = ?err.phase,
                        retryable = err.retryable,
                        error = %err.message,
                        evidence_error = %evidence_err.message,
                        "update healthy marker failed and failure evidence could not be persisted"
                    );
                    None
                }
            };
            // Audit DURABLY: the `evidence_recorded` boolean claims
            // durable evidence exists. If the audit event itself is
            // dropped (Enqueued + later writer failure), an operator
            // querying audit history will see no UpdateHealthyMarkerFailed
            // even though `update-startup-health-failure.json` is on
            // disk — contradictory forensics.
            if let Err(audit_err) = crate::logging::audit::audit_durable_for_state_dir(
                state_dir.to_path_buf(),
                crate::logging::audit::AuditEvent::UpdateHealthyMarkerFailed {
                    phase: err.phase,
                    retryable: err.retryable,
                    evidence_recorded: evidence.is_some(),
                },
            ) {
                tracing::error!(
                    audit_event = "update_healthy_marker_failed",
                    error = %audit_err,
                    "failed to durably audit healthy-marker failure"
                );
            }
            Err(UpdateHealthyMarkerError::Marker {
                error: err,
                evidence,
            })
        }
    }
}

fn mark_pending_update_healthy_inner(state_dir: &Path) -> Result<bool, UpdateError> {
    let Some(marker) = load_update_rollback_marker(state_dir)? else {
        return Ok(false);
    };
    if marker.startup_state != UpdateRollbackStartupState::Started {
        tracing::warn!(
            binary_path = %marker.binary_path,
            backup_path = %marker.backup_path,
            startup_state = ?marker.startup_state,
            "update healthy marker ignored because no updated-process startup is pending"
        );
        return Ok(false);
    }
    // Refuse a marker whose paths were tampered with before
    // touching either the marker or the backup file. A same-uid
    // attacker who plants a forged marker with attacker-chosen
    // `backup_path` could otherwise redirect the post-success
    // `remove_update_rollback_backup_after_healthy` to delete an
    // arbitrary file. See `verify_rollback_marker_paths` for the
    // canonical-binary-path contract.
    let binary_path = PathBuf::from(&marker.binary_path);
    let backup_path = PathBuf::from(&marker.backup_path);
    verify_rollback_marker_paths(&binary_path, &backup_path)?;

    clear_update_rollback_marker(state_dir)?;

    remove_update_rollback_backup_after_healthy(&backup_path)?;
    tracing::info!(
        binary_path = %marker.binary_path,
        backup_path = %marker.backup_path,
        "update rollback material cleared after successful startup"
    );
    Ok(true)
}

fn remove_update_rollback_backup_after_healthy(backup_path: &Path) -> Result<(), UpdateError> {
    #[cfg(test)]
    if TEST_FORCE_ROLLBACK_BACKUP_REMOVE_FAIL.swap(false, Ordering::SeqCst) {
        return Err(UpdateError::retryable(
            Some(UpdatePhase::Applied),
            format!(
                "forced update rollback backup removal failure '{}'",
                backup_path.display()
            ),
        ));
    }
    match fs::remove_file(backup_path) {
        Ok(()) => crate::paths::sync_parent_dir_blocking(backup_path).map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Applied),
                format!(
                    "failed to fsync update rollback backup removal '{}': {err}",
                    backup_path.display()
                ),
            )
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            crate::paths::sync_parent_dir_blocking(backup_path).map_err(|err| {
                UpdateError::retryable(
                    Some(UpdatePhase::Applied),
                    format!(
                        "failed to fsync update rollback backup parent after missing backup '{}': {err}",
                        backup_path.display()
                    ),
                )
            })?
        }
        Err(err) => {
            return Err(UpdateError::retryable(
                Some(UpdatePhase::Applied),
                format!(
                    "failed to remove update rollback backup '{}': {err}",
                    backup_path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn begin_pending_update_startup(state_dir: &Path) -> Result<Option<PathBuf>, UpdateError> {
    let Some(mut marker) = load_update_rollback_marker(state_dir)? else {
        return Ok(None);
    };
    // Verify the marker's recorded paths against the canonical
    // current-binary mapping BEFORE any state mutation. A same-uid
    // attacker who can write `update-rollback.json` could otherwise:
    //   (a) plant a Pending marker whose paths the attacker controls,
    //       and we'd flip it to Started + persist that record before
    //       any check; or
    //   (b) plant a Started marker pointing at an attacker-planted
    //       file whose sha256 equals the recorded `backup_sha256`, so
    //       `started_marker_backup_was_already_consumed` returns true
    //       and we flip the state to RolledBack — bypassing
    //       `restore_update_backup`'s verification entirely.
    // The RolledBack-as-noop branch needs no verify (it returns
    // before any mutation regardless).
    if !matches!(marker.startup_state, UpdateRollbackStartupState::RolledBack) {
        verify_rollback_marker_paths(
            Path::new(&marker.binary_path),
            Path::new(&marker.backup_path),
        )?;
    }
    match marker.startup_state {
        UpdateRollbackStartupState::Pending => {
            marker.startup_state = UpdateRollbackStartupState::Started;
            marker.started_at_ms = Some(now_ms());
            persist_update_rollback_marker(state_dir, &marker)?;
            tracing::info!(
                binary_path = %marker.binary_path,
                backup_path = %marker.backup_path,
                "update startup health pending; retaining rollback backup"
            );
            Ok(Some(PathBuf::from(marker.backup_path)))
        }
        UpdateRollbackStartupState::Started => {
            let backup_path = PathBuf::from(&marker.backup_path);
            if !backup_path.exists() && started_marker_backup_was_already_consumed(&marker)? {
                marker.startup_state = UpdateRollbackStartupState::RolledBack;
                marker.rolled_back_at_ms = Some(now_ms());
                persist_update_rollback_marker(state_dir, &marker)?;
                tracing::warn!(
                    binary_path = %marker.binary_path,
                    backup_path = %marker.backup_path,
                    "previous update rollback backup was already consumed; marking startup rollback complete"
                );
                return Ok(None);
            }
            restore_update_backup(&marker)?;
            marker.startup_state = UpdateRollbackStartupState::RolledBack;
            marker.rolled_back_at_ms = Some(now_ms());
            persist_update_rollback_marker(state_dir, &marker)?;
            tracing::warn!(
                binary_path = %marker.binary_path,
                backup_path = %marker.backup_path,
                "previous updated binary did not reach healthy startup; restored rollback backup on disk"
            );
            Ok(None)
        }
        UpdateRollbackStartupState::RolledBack => Ok(None),
    }
}

fn started_marker_backup_was_already_consumed(
    marker: &UpdateRollbackMarker,
) -> Result<bool, UpdateError> {
    let Some(expected_backup_hash) = marker.backup_sha256.as_deref() else {
        return Ok(false);
    };
    let binary_path = PathBuf::from(&marker.binary_path);
    if no_follow_regular_file_metadata(&binary_path).is_err() {
        return Ok(false);
    }
    // Symmetric `O_NOFOLLOW` hardening to
    // `persist_recoverable_rollback_marker_for_apply_result`'s
    // backup hash: refuse to hash through a symlink at the current
    // binary's path so the recovery probe cannot be tricked into
    // believing "current binary == backup" via a planted symlink.
    let current_hash = compute_sha256_no_follow(&binary_path)?;
    Ok(current_hash == expected_backup_hash)
}

fn restore_update_backup(marker: &UpdateRollbackMarker) -> Result<(), UpdateError> {
    let backup_path = PathBuf::from(&marker.backup_path);
    let binary_path = PathBuf::from(&marker.binary_path);

    // Bind the restore to the current executable. The marker is
    // owner-only state-dir content but a same-uid attacker (tool-
    // call escape, plugin host compromise) who can write
    // `update-rollback.json` could craft `binary_path` and
    // `backup_path` to redirect the restore: e.g.
    // `binary_path = /etc/profile.d/x.sh` (or any owner-writable
    // target outside the daemon's binary), `backup_path = <staged
    // attacker content>`. Refuse to restore unless `binary_path`
    // matches the current `current_exe()` canonical path AND
    // `backup_path` matches `backup_path_for_binary(current_exe)`.
    // Both checks together close the marker-controlled path-swap
    // class without breaking the legitimate restore flow (where
    // the marker was written by the same daemon that's now
    // recovering).
    verify_rollback_marker_paths(&binary_path, &backup_path)?;

    // Open backup with O_NOFOLLOW + held-fd validation. The prior
    // `no_follow_regular_file_metadata(&path)` → `fs::rename(&path, ..)`
    // shape validated one dirent and renamed another: a same-uid
    // attacker who swaps `backup_path` between the metadata check
    // and the rename has their substituted file restored over the
    // live `cara` binary. Content-bind the restore to the verified
    // fd instead — open once, hash once against `marker.backup_sha256`,
    // copy from THAT fd to current_path.
    let mut backup_file = match open_staged_for_apply_no_follow(&backup_path) {
        Ok(file) => file,
        Err(err) => {
            // open_staged_for_apply_no_follow already classifies
            // symlink / non-regular-file / missing, but it returns
            // those as non_retryable with phase=Applying. Reshape the
            // phase here so callers attribute the failure to the
            // rollback path.
            if err.message.contains("os error 2")
                || err.message.contains("No such file or directory")
            {
                return Err(UpdateError::non_retryable(
                    Some(UpdatePhase::Applied),
                    format!(
                        "update rollback backup '{}' is missing; cannot restore previous binary",
                        backup_path.display()
                    ),
                ));
            }
            return Err(UpdateError::non_retryable(
                Some(UpdatePhase::Applied),
                format!(
                    "update rollback backup '{}' is not a no-follow regular file at restore time: {}",
                    backup_path.display(),
                    err.message
                ),
            ));
        }
    };

    // Verify the marker-recorded backup hash against the actual fd
    // contents. Older markers may have `backup_sha256 == None` — refuse
    // those with an actionable error rather than restoring unverified
    // bytes over the live binary. The marker is daemon-written and
    // `compute_sha256_no_follow` populates it at apply time
    // (`persist_recoverable_rollback_marker_after_apply`), so a None
    // here means an old upgrade path that this binary cannot safely
    // service.
    let expected_backup_sha = marker.backup_sha256.as_deref().ok_or_else(|| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!(
                "rollback marker for '{}' is missing backup_sha256; refusing to restore unverified backup contents",
                backup_path.display()
            ),
        )
    })?;
    let actual_backup_sha = hash_open_file(&mut backup_file, &backup_path)?;
    if actual_backup_sha != expected_backup_sha {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!(
                "update rollback backup '{}' content hash {} does not match marker-recorded {}; refusing to restore",
                backup_path.display(),
                actual_backup_sha,
                expected_backup_sha
            ),
        ));
    }

    // Sanity-check the destination's file type if it exists. NotFound
    // is OK — `apply_staged_update_at_paths` renames current_path to
    // backup_path before copying staged, so a crash between rename
    // and copy leaves binary_path absent.
    match no_follow_regular_file_metadata(&binary_path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(UpdateError::non_retryable(
                Some(UpdatePhase::Applied),
                format!(
                    "update binary path '{}' is not a no-follow regular file at restore time: {err}",
                    binary_path.display()
                ),
            ));
        }
    }

    // Rewind the fd for the upcoming copy pass over the same bytes
    // we just hashed.
    use std::io::Seek;
    backup_file.seek(std::io::SeekFrom::Start(0)).map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!(
                "failed to rewind rollback backup '{}' before restore: {e}",
                backup_path.display()
            ),
        )
    })?;

    // Copy the held-fd bytes to a tmp file at the binary's parent and
    // atomically rename into place. The destination open uses
    // `create_new` so it cannot collide with a planted symlink or a
    // leftover from a crashed rollback attempt; rename is atomic on
    // POSIX so no half-restored window exists for the live cara
    // launcher to catch.
    let tmp_path = crate::paths::atomic_tmp_path(&binary_path, "rollback");
    let result = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Mode 0o755 so the restored binary is executable; the
            // staged-apply path also restores 0o755 via the same
            // umask-irrespective mechanism.
            options.mode(0o755).custom_flags(libc::O_NOFOLLOW);
        }
        let mut dest = options.open(&tmp_path)?;
        std::io::copy(&mut backup_file, &mut dest)?;
        dest.sync_all()?;
        drop(dest);
        fs::rename(&tmp_path, &binary_path)?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp_path);
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applied),
            format!(
                "failed to restore update rollback backup '{}' to '{}': {err}",
                backup_path.display(),
                binary_path.display()
            ),
        ));
    }

    // Best-effort cleanup of the original backup dirent — the live
    // binary now contains the verified backup bytes, so backup_path
    // is no longer needed. We do NOT propagate failure here: the
    // restore succeeded and the orphan will be picked up by
    // `cleanup_bak_files_near_exe` on next startup.
    let _ = fs::remove_file(&backup_path);

    crate::paths::sync_parent_dir_blocking(&binary_path).map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Applied),
            format!(
                "failed to fsync restored binary directory for '{}': {err}",
                binary_path.display()
            ),
        )
    })?;
    Ok(())
}

fn cleanup_bak_files_near_exe(state_dir: &Path, protected_backup: Option<&Path>) {
    let current_exe = match std::env::current_exe() {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(
                error = %err,
                "skipping old binary cleanup because current executable path is unavailable"
            );
            return;
        }
    };
    let exe = match current_exe.canonicalize() {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(
                path = %current_exe.display(),
                error = %err,
                "skipping old binary cleanup because current executable path could not be canonicalized"
            );
            return;
        }
    };
    let parent = match exe.parent() {
        Some(v) => v,
        None => return,
    };
    cleanup_bak_files_for_exe(&exe, parent, protected_backup, Some(state_dir));
}

fn cleanup_bak_files_for_exe(
    exe: &Path,
    parent: &Path,
    protected_backup: Option<&Path>,
    audit_state_dir: Option<&Path>,
) {
    // Snapshot the protected backup's identity (dev, inode on Unix;
    // canonical path on other platforms) ONCE at function entry. The
    // pre-fix loop re-stat'd the protected path on every candidate
    // comparison; a transient I/O error on the protected path during
    // one iteration would collapse `paths_refer_to_same_file` to
    // false, allowing the candidate-rejection to fall through and
    // the protected backup to be reaped. The captured snapshot is
    // not subject to per-iteration restat and survives transient
    // I/O on the protected path mid-loop.
    let protected_identity = match protected_backup {
        Some(protected) => match capture_protected_backup_identity(protected) {
            Ok(identity) => Some(identity),
            Err(_) => {
                tracing::warn!(
                    path = %protected.display(),
                    "skipping old binary cleanup because protected rollback backup path is not a no-follow regular file"
                );
                return;
            }
        },
        None => None,
    };
    let entries = match fs::read_dir(parent) {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(
                parent = %parent.display(),
                error = %err,
                "skipping old binary cleanup because executable directory could not be read"
            );
            return;
        }
    };
    let current_file_name = exe.file_name().and_then(|name| name.to_str());
    let current_stem = exe.file_stem().and_then(|stem| stem.to_str());
    let mut first_removed_path = None;
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(err) => {
                tracing::debug!(
                    parent = %parent.display(),
                    error = %err,
                    "skipping unreadable old binary cleanup entry"
                );
                continue;
            }
        };
        if let Some(identity) = protected_identity.as_ref() {
            match candidate_matches_protected_identity(&path, identity) {
                CandidateMatch::Matches => continue,
                CandidateMatch::DoesNotMatch => {}
                CandidateMatch::CandidateInaccessible => {
                    // We could not stat the candidate to prove it is
                    // distinct from the protected backup. Skip it —
                    // never reap a candidate we cannot definitively
                    // identify as non-protected.
                    tracing::debug!(
                        path = %path.display(),
                        "skipping update bak candidate whose identity could not be verified against the protected backup"
                    );
                    continue;
                }
            }
        }
        if old_binary_sibling_matches_exe(&path, current_file_name, current_stem) {
            if !record_update_rollback_backup_reaped(audit_state_dir, &path) {
                break;
            }
            if let Err(err) = fs::remove_file(&path) {
                tracing::warn!(path = %path.display(), error = %err, "failed to remove old binary");
            } else if first_removed_path.is_none() {
                first_removed_path = Some(path);
            }
        }
    }
    if let Some(path) = first_removed_path {
        if let Err(err) = crate::paths::sync_parent_dir_blocking(&path) {
            tracing::warn!(
                parent = %parent.display(),
                error = %err,
                "failed to fsync old binary cleanup directory"
            );
        }
    }
    // After the cleanup loop, re-verify the protected backup is
    // still present and unchanged. If it disappeared mid-loop the
    // operator should know — the rollback evidence may no longer
    // exist on disk.
    if let (Some(protected), Some(identity)) = (protected_backup, protected_identity.as_ref()) {
        match capture_protected_backup_identity(protected) {
            Ok(current) if &current == identity => {}
            Ok(_) => {
                tracing::warn!(
                    path = %protected.display(),
                    "protected rollback backup identity changed during old binary cleanup; rollback evidence may be inconsistent"
                );
            }
            Err(err) => {
                tracing::warn!(
                    path = %protected.display(),
                    error = %err,
                    "protected rollback backup vanished or became unreadable during old binary cleanup; rollback evidence may be missing"
                );
            }
        }
    }
}

/// Stable identity of a protected backup path. Captured once before
/// the cleanup loop; compared against each candidate without
/// re-stat'ing the protected path. This prevents a transient I/O
/// error on the protected path mid-loop from causing the cleanup to
/// reap the very file it was meant to preserve.
#[derive(Debug, PartialEq, Eq)]
enum ProtectedBackupIdentity {
    #[cfg(unix)]
    DevIno(u64, u64),
    #[cfg(not(unix))]
    Canonical(std::path::PathBuf),
}

enum CandidateMatch {
    Matches,
    DoesNotMatch,
    CandidateInaccessible,
}

fn capture_protected_backup_identity(protected: &Path) -> std::io::Result<ProtectedBackupIdentity> {
    let metadata = no_follow_regular_file_metadata(protected)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(ProtectedBackupIdentity::DevIno(
            metadata.dev(),
            metadata.ino(),
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        let canonical = protected.canonicalize()?;
        Ok(ProtectedBackupIdentity::Canonical(canonical))
    }
}

fn candidate_matches_protected_identity(
    candidate: &Path,
    protected_identity: &ProtectedBackupIdentity,
) -> CandidateMatch {
    let metadata = match no_follow_regular_file_metadata(candidate) {
        Ok(metadata) => metadata,
        Err(_) => return CandidateMatch::CandidateInaccessible,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let ProtectedBackupIdentity::DevIno(dev, ino) = protected_identity;
        if metadata.dev() == *dev && metadata.ino() == *ino {
            CandidateMatch::Matches
        } else {
            CandidateMatch::DoesNotMatch
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        let ProtectedBackupIdentity::Canonical(canonical) = protected_identity;
        match candidate.canonicalize() {
            Ok(candidate_canonical) if &candidate_canonical == canonical => CandidateMatch::Matches,
            Ok(_) => CandidateMatch::DoesNotMatch,
            Err(_) => CandidateMatch::CandidateInaccessible,
        }
    }
}

fn record_update_rollback_backup_reaped(audit_state_dir: Option<&Path>, path: &Path) -> bool {
    let Some(state_dir) = audit_state_dir else {
        return true;
    };
    let result = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::UpdateRollbackBackupReaped {
            path: redacted_update_rollback_backup_path(path),
        },
    );
    // Startup sibling cleanup is a one-shot boot reconciliation path, so it may
    // block on durable evidence through the audit writer's serialized disk
    // primitive before deleting rollback material. This does not change hot-path
    // audit semantics: routine runtime callers still use enqueue/drop policies.
    match result {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "failed to audit stale update rollback backup cleanup"
            );
            false
        }
    }
}

fn redacted_update_rollback_backup_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("<update-rollback-backup>/{name}"))
        .unwrap_or_else(|| "<update-rollback-backup>/<unknown>".to_string())
}

fn no_follow_regular_file_metadata(path: &Path) -> std::io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || update_metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("'{}' is not a no-follow regular file", path.display()),
        ));
    }
    Ok(metadata)
}

fn update_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    let left_meta = match no_follow_regular_file_metadata(left) {
        Ok(meta) => meta,
        _ => return false,
    };
    let right_meta = match no_follow_regular_file_metadata(right) {
        Ok(meta) => meta,
        _ => return false,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left_meta.dev() == right_meta.dev() && left_meta.ino() == right_meta.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left_meta, right_meta);
        match (left.canonicalize(), right.canonicalize()) {
            (Ok(left), Ok(right)) => left == right,
            _ => left == right,
        }
    }
}

fn old_binary_sibling_matches_exe(
    path: &Path,
    current_file_name: Option<&str>,
    current_stem: Option<&str>,
) -> bool {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    if !ext.eq_ignore_ascii_case("bak") && !ext.eq_ignore_ascii_case("old") {
        return false;
    }
    let Some(candidate_stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    current_stem.is_some_and(|stem| candidate_stem.eq_ignore_ascii_case(stem))
        || current_file_name.is_some_and(|name| candidate_stem.eq_ignore_ascii_case(name))
}

fn cleanup_stale_staged_updates(state_dir: &Path) {
    let updates_dir = state_dir.join("updates");
    let entries = match fs::read_dir(&updates_dir) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Only protect the startup-health-failure evidence while the
    // rollback marker is still in Pending or Started phase — i.e.
    // the operator hasn't yet finished the rollback cycle. Once the
    // marker transitions to RolledBack the rollback is complete and
    // the operator is on the prior binary; preserving the evidence
    // indefinitely accumulates a stale file on every boot for years
    // and pollutes `update.status` with a phantom failure that the
    // operator already acknowledged via rollback completion.
    let protect_startup_health_failure = match load_update_rollback_marker(state_dir) {
        Ok(Some(marker)) => matches!(
            marker.startup_state,
            UpdateRollbackStartupState::Pending | UpdateRollbackStartupState::Started
        ),
        Ok(None) => false,
        Err(err) => {
            // Defensively assume an in-flight rollback when the marker
            // is unreadable so we don't reap evidence that may still
            // be operator-relevant. But DO continue with the rest of
            // the cleanup (orphaned `*.tmp.*`, stale staged/bundle
            // files outside the active-update path set, expired
            // mark-attempted entries). The previous behavior bailed
            // out entirely on a corrupt rollback marker, defeating
            // the 7-day age-out for every other update artifact and
            // letting a single corrupt rollback.json leak unbounded
            // disk into `state_dir/updates/` until manual cleanup.
            tracing::warn!(
                phase = ?err.phase,
                retryable = err.retryable,
                error = %err.message,
                "rollback marker could not be parsed; preserving startup-health-failure evidence \
                 but continuing with general stale-update cleanup"
            );
            true
        }
    };
    let active_update_paths = match load_update_transaction(state_dir) {
        Ok(Some(tx)) => {
            let mut paths = Vec::new();
            if let Some(path) = tx.staged_path {
                paths.push(PathBuf::from(path));
            }
            if let Some(path) = tx.bundle_path {
                paths.push(PathBuf::from(path));
            }
            paths
        }
        Ok(None) => Vec::new(),
        Err(err) => {
            tracing::warn!(
                phase = ?err.phase,
                retryable = err.retryable,
                error = %err.message,
                "skipping stale update cleanup because transaction state could not be trusted"
            );
            return;
        }
    };
    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);
    for entry in entries.flatten() {
        let path = entry.path();
        if active_update_paths
            .iter()
            .any(|active| update_paths_match(active, &path))
        {
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name == UPDATE_TRANSACTION_FILENAME
                    || name == UPDATE_LOCK_FILENAME
                    || name == UPDATE_ROLLBACK_FILENAME
                    || (protect_startup_health_failure
                        && name == UPDATE_STARTUP_HEALTH_FAILURE_FILENAME)
            })
        {
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %err,
                    "skipping stale update cleanup entry because metadata could not be read"
                );
                continue;
            }
        };
        if metadata.file_type().is_symlink()
            || update_metadata_is_reparse_point(&metadata)
            || !metadata.is_file()
        {
            continue;
        }
        let stale = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > seven_days);
        if stale {
            if let Err(err) = fs::remove_file(&path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to remove stale staged file"
                );
            }
        }
    }
}

fn is_rate_limit_forbidden_body(body: &str) -> bool {
    let body_lower = body.to_ascii_lowercase();
    body_lower.contains("rate limit") || body_lower.contains("secondary rate")
}

fn sanitize_version_for_path(version: &str) -> String {
    let sanitized: String = version
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn is_retryable_release_response(status: reqwest::StatusCode, body: &str) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
        || (status == reqwest::StatusCode::FORBIDDEN && is_rate_limit_forbidden_body(body))
}

fn release_http_error_message(status: reqwest::StatusCode, body: &str) -> String {
    let reason = match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => "rate limited",
        reqwest::StatusCode::FORBIDDEN if is_rate_limit_forbidden_body(body) => "rate limited",
        reqwest::StatusCode::NOT_FOUND => "release not found",
        reqwest::StatusCode::UNAUTHORIZED => "authentication rejected",
        _ => "unexpected response",
    };
    format!("GitHub API returned HTTP {status} ({reason})")
}

fn resume_backoff_for_attempt(attempt: u32) -> Duration {
    match attempt {
        0 | 1 => Duration::from_secs(RESUME_BACKOFF_SHORT_SECS),
        2 => Duration::from_secs(RESUME_BACKOFF_MEDIUM_SECS),
        _ => Duration::from_secs(RESUME_BACKOFF_LONG_SECS),
    }
}

pub async fn fetch_release_info(
    current_version: &str,
    requested_version: Option<&str>,
) -> Result<GitHubRelease, UpdateError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|err| {
            UpdateError::retryable(
                None,
                format!("failed to construct update HTTP client: {err}"),
            )
        })?;

    let response = client
        .get(release_api_url(requested_version))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("cara/{current_version}"))
        .send()
        .await
        .map_err(|err| {
            UpdateError::retryable(
                None,
                format!("failed to fetch release info: {}", err.without_url()),
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = crate::net_util::read_response_body_text_capped(
            response,
            crate::net_util::MAX_RESPONSE_BODY_BYTES,
        )
        .await
        .unwrap_or_default();
        let message = release_http_error_message(status, &body);
        return if is_retryable_release_response(status, &body) {
            Err(UpdateError::retryable(None, message))
        } else {
            Err(UpdateError::non_retryable(None, message))
        };
    }

    let body_text = crate::net_util::read_response_body_text_capped(
        response,
        crate::net_util::MAX_RESPONSE_BODY_BYTES,
    )
    .await
    .map_err(|err| {
        UpdateError::non_retryable(None, format!("failed to read release JSON: {err}"))
    })?;
    serde_json::from_str::<GitHubRelease>(&body_text).map_err(|err| {
        UpdateError::non_retryable(None, format!("failed to parse release JSON: {err}"))
    })
}

fn find_asset<'a>(
    release: &'a GitHubRelease,
    asset_name: &str,
) -> Result<&'a GitHubAsset, UpdateError> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| {
            UpdateError::non_retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "no matching asset '{}' in release {} (available: {})",
                    asset_name,
                    release.tag_name,
                    release
                        .assets
                        .iter()
                        .map(|asset| asset.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })
}

async fn download_asset(
    client: &reqwest::Client,
    current_version: &str,
    url: &str,
) -> Result<Vec<u8>, UpdateError> {
    let response = client
        .get(url)
        .header("User-Agent", format!("cara/{current_version}"))
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!("failed to download artifact: {}", err.without_url()),
            )
        })?;

    if !response.status().is_success() {
        return Err(UpdateError::retryable(
            Some(UpdatePhase::Downloading),
            format!("artifact download returned status {}", response.status()),
        ));
    }

    // Cap the artifact body at 256 MiB. Carapace release binaries are
    // <100 MB; 256 MiB is a generous defense-in-depth against a
    // hostile / MITM-attacked release host streaming unbounded bytes
    // into RAM. The pre-cap `response.bytes()` call buffered the full
    // body before any size check, so a 300s download window at 1 Gbps
    // could materialize ~37 GB before the request timeout fired.
    const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024;
    let body = crate::net_util::read_response_body_bytes_capped(response, MAX_BUNDLE_BYTES)
        .await
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!("failed reading artifact bytes: {err}"),
            )
        })?;

    if body.is_empty() {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Downloading),
            "downloaded artifact is empty",
        ));
    }

    Ok(body)
}

async fn verify_bundle_signature(
    artifact_digest: Sha256Hash,
    bundle_bytes: &[u8],
    expected_identity: &str,
) -> Result<(), UpdateError> {
    let bundle = parse_sigstore_bundle(bundle_bytes)?;
    let trust_root = load_sigstore_trust_root().await?;
    verify_parsed_bundle_signature_with_trust_root(
        artifact_digest,
        bundle,
        expected_identity,
        trust_root,
    )
    .await
}

#[cfg(test)]
async fn verify_bundle_signature_digest(
    artifact_digest: Sha256Hash,
    bundle_bytes: &[u8],
    expected_identity: &str,
) -> Result<(), UpdateError> {
    let bundle = parse_sigstore_bundle(bundle_bytes)?;
    let trust_root = load_embedded_sigstore_trust_root()?;
    verify_parsed_bundle_signature_with_trust_root(
        artifact_digest,
        bundle,
        expected_identity,
        trust_root,
    )
    .await
}

async fn verify_parsed_bundle_signature_with_trust_root(
    artifact_digest: Sha256Hash,
    bundle: Bundle,
    expected_identity: &str,
    trust_root: TrustedRoot,
) -> Result<(), UpdateError> {
    let expected_identity = expected_identity.to_string();
    tokio::task::spawn_blocking(move || {
        verify_sigstore_bundle_digest_sync(
            artifact_digest,
            &bundle,
            &expected_identity,
            &trust_root,
        )
    })
    .await
    .map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Verified),
            format!("bundle verification worker task failed: {err}"),
        )
    })?
}

async fn load_sigstore_trust_root() -> Result<TrustedRoot, UpdateError> {
    TrustedRoot::from_tuf(TufConfig::production())
        .await
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Verified),
                format!("failed to initialize sigstore trust root: {err}"),
            )
        })
}

#[cfg(test)]
async fn load_sigstore_trust_root_with_config(
    config: TufConfig,
) -> Result<TrustedRoot, UpdateError> {
    TrustedRoot::from_tuf(config).await.map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Verified),
            format!("failed to initialize sigstore trust root: {err}"),
        )
    })
}

#[cfg(test)]
fn load_embedded_sigstore_trust_root() -> Result<TrustedRoot, UpdateError> {
    TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Verified),
            format!("failed to initialize sigstore trust root: {err}"),
        )
    })
}

fn parse_sigstore_bundle(bundle_bytes: &[u8]) -> Result<Bundle, UpdateError> {
    serde_json::from_slice::<Bundle>(bundle_bytes).map_err(|err| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Verified),
            format!("bundle parse failed: {err}"),
        )
    })
}

fn sha256_digest_bytes(data: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    Sha256Hash::from_bytes(digest)
}

#[cfg(test)]
fn parse_sigstore_digest(artifact_digest_hex: &str) -> Result<Sha256Hash, UpdateError> {
    Sha256Hash::from_hex(artifact_digest_hex).map_err(|err| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Verified),
            format!("invalid artifact digest: {err}"),
        )
    })
}

fn build_sigstore_policy(expected_identity: &str) -> VerificationPolicy {
    VerificationPolicy {
        identity: Some(expected_identity.to_string()),
        issuer: Some(EXPECTED_OIDC_ISSUER.to_string()),
        verify_tlog: true,
        verify_timestamp: true,
        verify_certificate: true,
        clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
    }
}

fn verify_sigstore_bundle_digest_sync(
    artifact_digest: Sha256Hash,
    bundle: &Bundle,
    expected_identity: &str,
    trust_root: &TrustedRoot,
) -> Result<(), UpdateError> {
    let policy = build_sigstore_policy(expected_identity);
    verify_sigstore_bundle_with_policy_sync(artifact_digest, bundle, &policy, trust_root)
}

fn verify_sigstore_bundle_with_policy_sync(
    artifact_digest: Sha256Hash,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trust_root: &TrustedRoot,
) -> Result<(), UpdateError> {
    let verifier = Verifier::new(trust_root);
    verifier
        .verify(artifact_digest, bundle, policy)
        .map_err(|err| {
            UpdateError::non_retryable(
                Some(UpdatePhase::Verified),
                format!("bundle verification failed: {err}"),
            )
        })?;
    Ok(())
}

fn checksum_entry_matches_asset(line: &str, asset_name: &str) -> bool {
    let Some(raw_name) = line.split_whitespace().nth(1) else {
        return false;
    };
    let normalized = raw_name.strip_prefix('*').unwrap_or(raw_name);
    let file_name = Path::new(normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(normalized);
    file_name == asset_name
}

fn make_new_transaction(version: &str, asset_name: &str) -> UpdateTransaction {
    let now = now_ms();
    UpdateTransaction {
        id: uuid::Uuid::new_v4().to_string(),
        version: version.to_string(),
        asset_name: asset_name.to_string(),
        state: UpdateTransactionState::InProgress,
        attempt: 0,
        max_attempts: DEFAULT_RESUME_MAX_ATTEMPTS,
        started_at_ms: now,
        updated_at_ms: now,
        staged_path: None,
        bundle_path: None,
        sha256: None,
        last_error: None,
        phase: UpdatePhase::Created,
        retryable: true,
        apply_confirmed_until_ms: None,
        extra: BTreeMap::new(),
    }
}

fn transition(
    tx: &mut UpdateTransaction,
    phase: UpdatePhase,
    state: UpdateTransactionState,
    last_error: Option<String>,
    retryable: bool,
) {
    let from_phase = tx.phase;
    let from_state = tx.state;
    let error_for_log = last_error.clone();
    tx.phase = phase;
    tx.state = state;
    tx.last_error = last_error;
    tx.retryable = retryable;
    tx.updated_at_ms = now_ms();
    tracing::debug!(
        transaction_id = %tx.id,
        from_phase = ?from_phase,
        to_phase = ?phase,
        from_state = ?from_state,
        to_state = ?state,
        retryable,
        last_error = ?error_for_log,
        "update transaction transition"
    );
}

fn record_failure(
    state_dir: &Path,
    tx: &mut UpdateTransaction,
    error: &UpdateError,
) -> Result<(), UpdateError> {
    transition(
        tx,
        UpdatePhase::Failed,
        UpdateTransactionState::Failed,
        Some(error.message.clone()),
        error.retryable,
    );
    persist_update_transaction(state_dir, tx)
}

async fn run_transaction_once(
    request: &InstallRequest,
    tx: &mut UpdateTransaction,
    release: Option<GitHubRelease>,
) -> Result<InstallOutcome, UpdateError> {
    if tx.attempt >= tx.max_attempts {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Failed),
            format!(
                "update transaction retry budget exhausted ({}/{})",
                tx.attempt, tx.max_attempts
            ),
        ));
    }

    tx.attempt = tx.attempt.saturating_add(1);
    tx.updated_at_ms = now_ms();
    persist_update_transaction(&request.state_dir, tx)?;

    let release = match release {
        Some(v) => v,
        None => fetch_release_info(&request.current_version, Some(&tx.version)).await?,
    };

    let asset_name = tx.asset_name.clone();
    let binary_asset = find_asset(&release, &asset_name)?;
    let bundle_asset = find_asset(&release, &expected_bundle_name(&asset_name))?;

    transition(
        tx,
        UpdatePhase::Downloading,
        UpdateTransactionState::InProgress,
        None,
        true,
    );
    persist_update_transaction(&request.state_dir, tx)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!("failed to construct update HTTP client: {err}"),
            )
        })?;

    let binary_bytes = download_asset(
        &client,
        &request.current_version,
        &binary_asset.browser_download_url,
    )
    .await?;
    let bundle_bytes = download_asset(
        &client,
        &request.current_version,
        &bundle_asset.browser_download_url,
    )
    .await?;

    let staged_path = update_staging_path(&request.state_dir, &tx.version);
    let bundle_path = update_bundle_path(&request.state_dir, &tx.version);
    if let Some(parent) = staged_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!("failed to create update staging directory: {err}"),
            )
        })?;
    }

    // SECURITY: open the staged file with O_NOFOLLOW + O_EXCL via
    // OpenOptions, after removing any leftover file from a prior
    // failed staging. The previous `tokio::fs::File::create` (=
    // O_CREAT|O_WRONLY|O_TRUNC, no O_NOFOLLOW) followed symlinks,
    // and the predictable `state_dir/updates/cara-<version>` path
    // is a same-uid attacker symlink-plant vector: planted symlink
    // → daemon writes downloaded binary bytes to attacker-chosen
    // target, then the path-based `set_permissions` below would
    // chmod the redirected target 0o755. Companion to the Batch-
    // 44/48/49 atomic-write sweep that missed this site.
    let _ = tokio::fs::remove_file(&staged_path).await;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut staged_file = options.open(&staged_path).await.map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Downloading),
            format!(
                "failed to create staged file '{}': {err}",
                staged_path.display()
            ),
        )
    })?;
    staged_file.write_all(&binary_bytes).await.map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Downloading),
            format!(
                "failed to write staged file '{}': {err}",
                staged_path.display()
            ),
        )
    })?;
    staged_file.flush().await.map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Downloading),
            format!(
                "failed to flush staged file '{}': {err}",
                staged_path.display()
            ),
        )
    })?;
    staged_file.sync_all().await.map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Downloading),
            format!(
                "failed to sync staged file '{}': {err}",
                staged_path.display()
            ),
        )
    })?;

    // Same hardening for the sigstore bundle file.
    let _ = tokio::fs::remove_file(&bundle_path).await;
    {
        let mut bundle_options = tokio::fs::OpenOptions::new();
        bundle_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            bundle_options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut bundle_file = bundle_options.open(&bundle_path).await.map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "failed to create bundle file '{}': {err}",
                    bundle_path.display()
                ),
            )
        })?;
        bundle_file.write_all(&bundle_bytes).await.map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "failed to write bundle file '{}': {err}",
                    bundle_path.display()
                ),
            )
        })?;
        bundle_file.flush().await.map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "failed to flush bundle file '{}': {err}",
                    bundle_path.display()
                ),
            )
        })?;
        // DURABILITY: fsync the bundle inode so a crash between the
        // OS page cache and the next dispatch doesn't leave the
        // transaction-referenced bundle file truncated or zero-length.
        // The staged_file above already calls sync_all; this brings
        // the bundle into parity. Without this, resume after a power
        // loss could hit an unrecoverable signature-verify failure on
        // a transaction that already claims `Downloaded`.
        bundle_file.sync_all().await.map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "failed to sync bundle file '{}': {err}",
                    bundle_path.display()
                ),
            )
        })?;
    }

    // DURABILITY: fsync the staging directory so the new dirents
    // (staged binary + sigstore bundle) survive a power loss. Without
    // a parent-dir fsync, the inodes may be flushed but their dirents
    // not yet committed, leaving the transaction record referencing
    // files that don't exist on resume. `sync_parent_dir_blocking`
    // takes a path whose parent it fsyncs — passing staged_path
    // targets the shared `state_dir/updates/` directory which is
    // also bundle_path's parent.
    let staged_path_owned = staged_path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::paths::sync_parent_dir_blocking(&staged_path_owned))
        .await
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!("failed to spawn fsync task for update staging dir: {err}"),
            )
        })?
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!("failed to fsync update staging dir: {err}"),
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // SECURITY: fd-based set_permissions (via the open
        // staged_file handle's underlying std::fs::File) — the
        // path-based variant follows symlinks and could chmod the
        // redirected target if the dirent was swapped between open
        // and chmod. Using the held fd anchors the chmod to the
        // exact dirent we already opened with O_NOFOLLOW above.
        let staged_std = staged_file.into_std().await;
        staged_std
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|err| {
                UpdateError::retryable(
                    Some(UpdatePhase::Downloading),
                    format!(
                        "failed to set executable permissions on staged file '{}': {err}",
                        staged_path.display()
                    ),
                )
            })?;
    }

    let staged_digest = sha256_digest_bytes(&binary_bytes);
    let staged_hash = hex::encode(staged_digest.as_bytes());
    tx.staged_path = Some(staged_path.to_string_lossy().to_string());
    tx.bundle_path = Some(bundle_path.to_string_lossy().to_string());
    tx.sha256 = Some(staged_hash.clone());
    transition(
        tx,
        UpdatePhase::Downloaded,
        UpdateTransactionState::InProgress,
        None,
        true,
    );
    persist_update_transaction(&request.state_dir, tx)?;

    let expected_identity = expected_identity_for_tag(&version_to_tag(&tx.version));
    verify_bundle_signature(staged_digest, &bundle_bytes, &expected_identity).await?;

    let checksum_asset = release
        .assets
        .iter()
        .find(|asset| asset.name == expected_checksum_name());
    let mut checksum_verified = false;
    if let Some(checksum_asset) = checksum_asset {
        let checksum_bytes = download_asset(
            &client,
            &request.current_version,
            &checksum_asset.browser_download_url,
        )
        .await?;
        let checksum_text = String::from_utf8(checksum_bytes).map_err(|err| {
            UpdateError::non_retryable(
                Some(UpdatePhase::Verified),
                format!("checksum file is not UTF-8 text: {err}"),
            )
        })?;

        let entry = checksum_text
            .lines()
            .find(|line| checksum_entry_matches_asset(line, &asset_name));
        if let Some(line) = entry {
            verify_checksum(&staged_hash, line)?;
            checksum_verified = true;
        } else {
            tracing::warn!(
                transaction_id = %tx.id,
                checksum_file = %expected_checksum_name(),
                asset_name = %asset_name,
                "checksum file present but no matching entry for update asset"
            );
        }
    }
    tracing::info!(
        transaction_id = %tx.id,
        version = %tx.version,
        expected_identity = %expected_identity,
        checksum_verified,
        "update artifact verification passed"
    );

    transition(
        tx,
        UpdatePhase::Verified,
        UpdateTransactionState::InProgress,
        None,
        true,
    );
    persist_update_transaction(&request.state_dir, tx)?;

    if !request.apply_update {
        return Ok(InstallOutcome {
            version: tx.version.clone(),
            staged_path: tx.staged_path.clone().unwrap_or_default(),
            applied: false,
            apply_result: None,
            verification: VerificationSummary {
                bundle_verified: true,
                checksum_verified,
                expected_identity,
            },
            transaction: Some(tx.clone()),
            resumed: false,
            attempt: tx.attempt,
        });
    }

    if request.apply_confirmation == UpdateApplyConfirmation::Automatic
        && !apply_confirmation_is_fresh(tx, now_ms())
    {
        return Err(stale_apply_confirmation_error(tx));
    }

    transition(
        tx,
        UpdatePhase::Applying,
        UpdateTransactionState::InProgress,
        None,
        true,
    );
    persist_update_transaction(&request.state_dir, tx)?;

    let staged_path = tx.staged_path.clone().unwrap_or_default();
    let expected_hash = tx.sha256.clone().ok_or_else(|| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            "missing staged artifact hash before apply",
        )
    })?;
    // The apply path itself now binds the held-fd hash to
    // `expected_hash` BEFORE any rename/copy (see Batch 71). The
    // prior `compute_sha256_blocking` pre-check was redundant on the
    // happy path AND insufficient on the attack path (it re-opened
    // by name, leaving a swap window before `apply_staged_update_blocking`
    // re-opened by name again). Drop the pre-check; the apply-time
    // check is now load-bearing.
    let apply_result = apply_staged_update_blocking(staged_path, expected_hash).await?;
    if let Err(err) =
        persist_recoverable_rollback_marker_after_apply(&request.state_dir, &apply_result)
    {
        let backup_path = backup_path_for_binary(Path::new(&apply_result.binary_path));
        tracing::error!(
            phase = ?err.phase,
            retryable = err.retryable,
            error = %err.message,
            backup_path = %backup_path.display(),
            "update applied but rollback marker could not be persisted; rollback backup may be orphaned and removed by startup cleanup"
        );
        return Err(err);
    }

    transition(
        tx,
        UpdatePhase::Applied,
        UpdateTransactionState::Applied,
        None,
        false,
    );
    persist_update_transaction(&request.state_dir, tx)?;
    clear_update_transaction(&request.state_dir)?;
    cleanup_old_binaries(&request.state_dir);

    Ok(InstallOutcome {
        version: tx.version.clone(),
        staged_path: tx.staged_path.clone().unwrap_or_default(),
        applied: true,
        apply_result: Some(apply_result),
        verification: VerificationSummary {
            bundle_verified: true,
            checksum_verified,
            expected_identity,
        },
        transaction: None,
        resumed: false,
        attempt: tx.attempt,
    })
}

async fn prepare_transaction(
    request: &InstallRequest,
) -> Result<(UpdateTransaction, GitHubRelease), UpdateError> {
    let release = fetch_release_info(
        &request.current_version,
        request.requested_version.as_deref(),
    )
    .await?;
    let version = tag_to_version(&release.tag_name);
    let asset_name = expected_asset_name();
    find_asset(&release, &asset_name)?;
    find_asset(&release, &expected_bundle_name(&asset_name))?;

    let mut tx = make_new_transaction(&version, &asset_name);
    tx.max_attempts = DEFAULT_RESUME_MAX_ATTEMPTS;
    if request.apply_update && request.apply_confirmation == UpdateApplyConfirmation::Explicit {
        refresh_apply_confirmation(&mut tx);
    }
    persist_update_transaction(&request.state_dir, &tx)?;
    Ok((tx, release))
}

fn requested_version_matches_transaction(
    requested_version: &str,
    transaction_version: &str,
) -> bool {
    tag_to_version(requested_version) == transaction_version
}

fn should_restart_transaction_for_requested_version(
    requested_version: Option<&str>,
    transaction_version: &str,
) -> bool {
    requested_version.is_some_and(|requested| {
        !requested_version_matches_transaction(requested, transaction_version)
    })
}

async fn apply_staged_update_blocking(
    staged_path: String,
    expected_hash: String,
) -> Result<ApplyResult, UpdateError> {
    tokio::task::spawn_blocking(move || apply_staged_update(&staged_path, Some(&expected_hash)))
        .await
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Applying),
                format!("failed to join staged apply task: {err}"),
            )
        })?
}

async fn install_with_existing_transaction(
    request: &InstallRequest,
    existing: Option<UpdateTransaction>,
) -> Result<InstallOutcome, UpdateError> {
    let (mut tx, release_for_first_run) = match existing {
        Some(mut tx) => {
            if tx.state == UpdateTransactionState::Applied {
                tracing::info!(
                    transaction_id = %tx.id,
                    phase = ?tx.phase,
                    state = ?tx.state,
                    "clearing applied transaction and starting a fresh update attempt"
                );
                clear_update_transaction(&request.state_dir)?;
                let (tx, release) = prepare_transaction(request).await?;
                (tx, Some(release))
            } else if tx.state == UpdateTransactionState::Failed && !tx.retryable {
                tracing::info!(
                    transaction_id = %tx.id,
                    transaction_version = %tx.version,
                    "clearing non-retryable transaction and starting a fresh update attempt"
                );
                clear_update_transaction(&request.state_dir)?;
                let (tx, release) = prepare_transaction(request).await?;
                (tx, Some(release))
            } else if should_restart_transaction_for_requested_version(
                request.requested_version.as_deref(),
                &tx.version,
            ) {
                tracing::info!(
                    transaction_id = %tx.id,
                    transaction_version = %tx.version,
                    requested_version = ?request.requested_version,
                    "clearing transaction due to requested-version mismatch and starting a fresh update attempt"
                );
                clear_update_transaction(&request.state_dir)?;
                let (tx, release) = prepare_transaction(request).await?;
                (tx, Some(release))
            } else {
                if transaction_resume_pending(&tx) {
                    tracing::info!(
                        transaction_id = %tx.id,
                        phase = ?tx.phase,
                        state = ?tx.state,
                        attempt = tx.attempt,
                        max_attempts = tx.max_attempts,
                        "resuming existing update transaction"
                    );
                } else {
                    tracing::info!(
                        transaction_id = %tx.id,
                        phase = ?tx.phase,
                        state = ?tx.state,
                        attempt = tx.attempt,
                        max_attempts = tx.max_attempts,
                        "found non-resumable existing update transaction; re-running once to surface terminal state"
                    );
                }
                if request.apply_update {
                    match request.apply_confirmation {
                        UpdateApplyConfirmation::Explicit => {
                            refresh_apply_confirmation(&mut tx);
                        }
                        UpdateApplyConfirmation::Automatic => {
                            if !apply_confirmation_is_fresh(&tx, now_ms()) {
                                let err = stale_apply_confirmation_error(&tx);
                                record_failure(&request.state_dir, &mut tx, &err)?;
                                return Err(err);
                            }
                        }
                    }
                }
                tx.updated_at_ms = now_ms();
                persist_update_transaction(&request.state_dir, &tx)?;
                (tx, None)
            }
        }
        None => {
            let (tx, release) = prepare_transaction(request).await?;
            (tx, Some(release))
        }
    };

    let resumed = release_for_first_run.is_none();
    let outcome = run_transaction_once(request, &mut tx, release_for_first_run).await;
    match outcome {
        Ok(mut value) => {
            value.resumed = resumed;
            value.attempt = tx.attempt;
            Ok(value)
        }
        Err(err) => {
            record_failure(&request.state_dir, &mut tx, &err)?;
            Err(err)
        }
    }
}

async fn install_with_transaction(request: &InstallRequest) -> Result<InstallOutcome, UpdateError> {
    let existing = load_update_transaction(&request.state_dir)?;
    install_with_existing_transaction(request, existing).await
}

pub async fn install_or_resume(request: InstallRequest) -> Result<InstallOutcome, UpdateError> {
    let _guard = acquire_update_operation_guard(&request.state_dir).await?;
    install_with_transaction(&request).await
}

pub async fn install_or_resume_with_snapshot(
    mut request: InstallRequest,
    latest_version: Option<String>,
    update_available: bool,
    force: bool,
) -> Result<InstallOutcome, UpdateError> {
    let _guard = acquire_update_operation_guard(&request.state_dir).await?;
    let existing = load_update_transaction(&request.state_dir)?;
    let resume_pending = existing.as_ref().is_some_and(transaction_resume_pending);
    if !update_available && !force && !resume_pending {
        return Err(UpdateError::non_retryable_with_code(
            None,
            UpdateErrorCode::NoUpdateAvailable,
            NO_UPDATE_AVAILABLE_MESSAGE.to_string(),
        ));
    }

    request.requested_version = if resume_pending {
        existing.as_ref().map(|tx| tx.version.clone())
    } else {
        latest_version
    };

    if request.requested_version.is_none() {
        return Err(UpdateError::non_retryable_with_code(
            None,
            UpdateErrorCode::LatestVersionUnknown,
            LATEST_VERSION_UNKNOWN_MESSAGE.to_string(),
        ));
    }

    install_with_existing_transaction(&request, existing).await
}

pub async fn auto_resume_with_backoff(
    state_dir: PathBuf,
    current_version: String,
    apply_update: bool,
    mut shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<Option<InstallOutcome>, UpdateError> {
    let mut tx;

    loop {
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            return Ok(None);
        }

        tx = match load_update_transaction(&state_dir)? {
            Some(next_tx) => next_tx,
            None => return Ok(None),
        };
        if !transaction_resume_pending(&tx) {
            return Ok(None);
        }

        let request = InstallRequest {
            current_version: current_version.clone(),
            state_dir: state_dir.clone(),
            requested_version: Some(tx.version.clone()),
            apply_update,
            apply_confirmation: UpdateApplyConfirmation::Automatic,
        };
        match install_or_resume(request).await {
            Ok(outcome) => return Ok(Some(outcome)),
            Err(err) if err.retryable => {
                tx = match load_update_transaction(&state_dir)? {
                    Some(next_tx) => next_tx,
                    None => return Ok(None),
                };
                if tx.state == UpdateTransactionState::Failed && tx.attempt >= tx.max_attempts {
                    return Err(UpdateError::non_retryable(
                        err.phase,
                        format!(
                            "{} (retry budget exhausted at attempt {}/{})",
                            err.message, tx.attempt, tx.max_attempts
                        ),
                    ));
                }
                if !transaction_resume_pending(&tx) {
                    return Ok(None);
                }
                let backoff = resume_backoff_for_attempt(tx.attempt);
                if let Some(shutdown) = shutdown_rx.as_mut() {
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                return Ok(None);
                            }
                        }
                    }
                } else {
                    tokio::time::sleep(backoff).await;
                }
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V070_SHA256SUMS_DIGEST: &str =
        "acc4012c1a51190fc354e4e5d77ebe0779097e36d30e3ce523efb05581394163";
    // The leaf certificate in this bundle is expired relative to current wall clock time,
    // but Sigstore verification correctly anchors certificate validity to the verified
    // transparency-log integrated time carried in the bundle, so this fixture remains stable.
    const V070_SHA256SUMS_BUNDLE: &[u8] =
        include_bytes!("../../tests/fixtures/update/v0.7.0-sha256sums.bundle");

    static TEST_APPLY_FAILURE_FLAGS_LOCK: LazyLock<std::sync::Mutex<()>> =
        LazyLock::new(|| std::sync::Mutex::new(()));

    struct ApplyFailureFlagsGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl ApplyFailureFlagsGuard {
        fn lock() -> Self {
            let lock = TEST_APPLY_FAILURE_FLAGS_LOCK
                .lock()
                .expect("apply failure flags lock poisoned");
            TEST_FORCE_COPY_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_RESTORE_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_MARKER_PERSIST_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_MARKER_CLEAR_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_MARKER_FSYNC_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_BACKUP_REMOVE_FAIL.store(false, Ordering::SeqCst);
            // Test fixtures exercise the marker lifecycle against
            // synthetic temp-dir paths that cannot match the
            // nextest binary's `current_exe()`. Skip the canonical-
            // path verification under the lock so production-only
            // assertions don't false-fail.
            TEST_SKIP_ROLLBACK_MARKER_PATH_VERIFY.store(true, Ordering::SeqCst);
            Self { _lock: lock }
        }

        fn force_copy_failure(&self) {
            TEST_FORCE_COPY_FAIL.store(true, Ordering::SeqCst);
        }

        fn force_restore_failure(&self) {
            TEST_FORCE_RESTORE_FAIL.store(true, Ordering::SeqCst);
        }

        fn force_rollback_marker_persist_failure(&self) {
            TEST_FORCE_ROLLBACK_MARKER_PERSIST_FAIL.store(true, Ordering::SeqCst);
        }

        fn force_rollback_marker_clear_failure(&self) {
            TEST_FORCE_ROLLBACK_MARKER_CLEAR_FAIL.store(true, Ordering::SeqCst);
        }

        fn force_rollback_marker_fsync_failure(&self) {
            TEST_FORCE_ROLLBACK_MARKER_FSYNC_FAIL.store(true, Ordering::SeqCst);
        }

        fn force_rollback_backup_remove_failure(&self) {
            TEST_FORCE_ROLLBACK_BACKUP_REMOVE_FAIL.store(true, Ordering::SeqCst);
        }
    }

    impl Drop for ApplyFailureFlagsGuard {
        fn drop(&mut self) {
            TEST_FORCE_COPY_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_RESTORE_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_MARKER_PERSIST_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_MARKER_CLEAR_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_MARKER_FSYNC_FAIL.store(false, Ordering::SeqCst);
            TEST_FORCE_ROLLBACK_BACKUP_REMOVE_FAIL.store(false, Ordering::SeqCst);
            TEST_SKIP_ROLLBACK_MARKER_PATH_VERIFY.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_expected_asset_name_matches_release_pattern() {
        let asset = expected_asset_name();
        assert!(asset.starts_with("cara-"));
        assert!(!asset.contains(' '));
    }

    #[test]
    fn test_expected_identity_for_tag() {
        let identity = expected_identity_for_tag("v0.1.0-preview12");
        assert!(identity.starts_with(EXPECTED_IDENTITY_PREFIX));
        assert!(identity.ends_with("v0.1.0-preview12"));
    }

    #[test]
    fn test_release_http_status_retryable_classification() {
        assert!(is_retryable_release_response(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            ""
        ));
        assert!(is_retryable_release_response(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ""
        ));
        assert!(!is_retryable_release_response(
            reqwest::StatusCode::NOT_FOUND,
            ""
        ));
    }

    #[test]
    fn test_release_http_status_forbidden_retryable_only_for_rate_limit() {
        assert!(is_retryable_release_response(
            reqwest::StatusCode::FORBIDDEN,
            "API rate limit exceeded for user"
        ));
        assert!(!is_retryable_release_response(
            reqwest::StatusCode::FORBIDDEN,
            "forbidden"
        ));
    }

    #[test]
    fn test_requested_version_matches_transaction_with_or_without_v_prefix() {
        assert!(requested_version_matches_transaction(
            "v0.1.0-preview12",
            "0.1.0-preview12"
        ));
        assert!(requested_version_matches_transaction(
            "0.1.0-preview12",
            "0.1.0-preview12"
        ));
        assert!(!requested_version_matches_transaction(
            "v0.1.0-preview11",
            "0.1.0-preview12"
        ));
    }

    #[test]
    fn test_should_restart_transaction_for_requested_version() {
        assert!(!should_restart_transaction_for_requested_version(
            None,
            "0.1.0-preview12"
        ));
        assert!(!should_restart_transaction_for_requested_version(
            Some("v0.1.0-preview12"),
            "0.1.0-preview12"
        ));
        assert!(should_restart_transaction_for_requested_version(
            Some("v0.1.0-preview11"),
            "0.1.0-preview12"
        ));
    }

    #[test]
    fn test_sanitize_version_for_path_replaces_unsafe_chars() {
        assert_eq!(
            sanitize_version_for_path("../../v0.1.0-preview12"),
            ".._.._v0.1.0-preview12"
        );
        assert_eq!(
            sanitize_version_for_path("v0.1.0+build/metadata"),
            "v0.1.0_build_metadata"
        );
    }

    #[test]
    fn test_resume_backoff_for_attempt() {
        assert_eq!(resume_backoff_for_attempt(0), Duration::from_secs(5));
        assert_eq!(resume_backoff_for_attempt(1), Duration::from_secs(5));
        assert_eq!(resume_backoff_for_attempt(2), Duration::from_secs(15));
        assert_eq!(resume_backoff_for_attempt(3), Duration::from_secs(45));
        assert_eq!(resume_backoff_for_attempt(10), Duration::from_secs(45));
    }

    #[test]
    fn test_verify_checksum_accepts_gnu_format() {
        let hash = sha256_bytes(b"hello");
        let line = format!("{hash}  cara-x86_64-linux");
        verify_checksum(&hash, &line).expect("checksum should pass");
    }

    #[test]
    fn test_sha256_digest_bytes_hex_matches_sha256_bytes() {
        let digest = sha256_digest_bytes(b"hello");
        assert_eq!(hex::encode(digest.as_bytes()), sha256_bytes(b"hello"));
    }

    #[test]
    fn test_verify_checksum_rejects_mismatch() {
        let err = verify_checksum(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  cara-x86_64-linux",
        )
        .expect_err("checksum mismatch should fail");
        assert!(err.message.contains("mismatch"));
    }

    #[test]
    fn test_verify_checksum_rejects_invalid_hash() {
        let err = verify_checksum(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "not-a-hash",
        )
        .expect_err("invalid checksum should fail");
        assert!(err.message.contains("valid SHA-256"));
    }

    #[test]
    fn test_checksum_entry_matches_asset_supports_binary_mode_prefix() {
        assert!(checksum_entry_matches_asset(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  *cara-x86_64-linux",
            "cara-x86_64-linux"
        ));
    }

    #[test]
    fn test_checksum_entry_matches_asset_supports_path_prefixes() {
        assert!(checksum_entry_matches_asset(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ./dist/cara-x86_64-linux",
            "cara-x86_64-linux"
        ));
    }

    #[test]
    fn test_transaction_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        tx.attempt = 2;
        let staged = update_staging_path(dir.path(), "0.1.0")
            .to_string_lossy()
            .into_owned();
        let bundle = update_bundle_path(dir.path(), "0.1.0")
            .to_string_lossy()
            .into_owned();
        tx.staged_path = Some(staged.clone());
        tx.bundle_path = Some(bundle.clone());
        persist_update_transaction(dir.path(), &tx).unwrap();

        let loaded = load_update_transaction(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.version, "0.1.0");
        assert_eq!(loaded.attempt, 2);
        assert_eq!(loaded.staged_path.as_deref(), Some(staged.as_str()));
        assert_eq!(loaded.bundle_path.as_deref(), Some(bundle.as_str()));
    }

    #[test]
    fn test_transaction_validation_rejects_tampered_asset_name() {
        let dir = tempfile::tempdir().unwrap();
        let tx = make_new_transaction("0.1.0", "cara-wrong-arch-linux");
        let path = update_transaction_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&tx).unwrap()).unwrap();

        let err = load_update_transaction(dir.path()).expect_err("wrong asset must reject");
        assert!(err.message.contains("does not match this platform"));
    }

    #[cfg(unix)]
    #[test]
    fn test_update_state_dir_is_chmod_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let tx = make_new_transaction("0.1.0", &expected_asset_name());
        persist_update_transaction(dir.path(), &tx).unwrap();

        let state_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        let updates_mode = std::fs::metadata(dir.path().join("updates"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(state_mode, 0o700);
        assert_eq!(updates_mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn test_update_marker_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let tx = make_new_transaction("0.1.0", &expected_asset_name());
        persist_update_transaction(dir.path(), &tx).unwrap();

        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        persist_update_startup_health_failure(
            dir.path(),
            &UpdateError::retryable(Some(UpdatePhase::Applied), "startup marker failed"),
        )
        .unwrap();

        for path in [
            update_transaction_path(dir.path()),
            update_rollback_marker_path(dir.path()),
            update_startup_health_failure_path(dir.path()),
        ] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be owner-only", path.display());
        }
    }

    #[test]
    fn test_transaction_resume_pending_logic() {
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        assert!(transaction_resume_pending(&tx));

        tx.state = UpdateTransactionState::Failed;
        tx.retryable = true;
        tx.attempt = 1;
        tx.max_attempts = 3;
        assert!(transaction_resume_pending(&tx));

        tx.attempt = 3;
        assert!(!transaction_resume_pending(&tx));

        tx.state = UpdateTransactionState::Applied;
        assert!(!transaction_resume_pending(&tx));
    }

    #[test]
    fn test_clear_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let tx = make_new_transaction("0.1.0", &expected_asset_name());
        persist_update_transaction(dir.path(), &tx).unwrap();
        clear_update_transaction(dir.path()).unwrap();
        assert!(load_update_transaction(dir.path()).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_auto_resume_rejects_stale_apply_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        tx.state = UpdateTransactionState::InProgress;
        tx.phase = UpdatePhase::Applying;
        tx.retryable = true;
        tx.apply_confirmed_until_ms = Some(now_ms().saturating_sub(1));
        persist_update_transaction(dir.path(), &tx).unwrap();

        let err =
            auto_resume_with_backoff(dir.path().to_path_buf(), "0.1.0".to_string(), true, None)
                .await
                .expect_err("stale automatic apply resume must fail");
        assert!(!err.retryable);
        assert!(err.message.contains("requires fresh operator confirmation"));

        let failed = load_update_transaction(dir.path()).unwrap().unwrap();
        assert_eq!(failed.state, UpdateTransactionState::Failed);
        assert!(!failed.retryable);
    }

    #[test]
    fn test_pending_update_startup_marks_started_then_healthy_clears_backup() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Pending,
                started_at_ms: None,
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        let protected = begin_pending_update_startup(dir.path())
            .unwrap()
            .expect("pending marker should protect backup");
        assert_eq!(protected, backup);
        let marker = load_update_rollback_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.startup_state, UpdateRollbackStartupState::Started);

        mark_pending_update_healthy(dir.path()).unwrap();
        assert!(!backup.exists());
        assert!(load_update_rollback_marker(dir.path()).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_restore_update_backup_revalidates_symlinked_backup_at_restore_time() {
        let _guard = ApplyFailureFlagsGuard::lock();
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        let outside = dir.path().join("outside-old-binary");
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&outside, b"outside-old").unwrap();
        symlink(&outside, &backup).unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"new"),
            backup_sha256: Some(sha256_bytes(b"old")),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Started,
            started_at_ms: Some(now_ms()),
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };

        let err = restore_update_backup(&marker)
            .expect_err("restore must reject symlinked rollback backup at rename time");

        assert!(err.message.contains("not a no-follow regular file"));
        assert_eq!(std::fs::read(&binary).unwrap(), b"new");
        assert!(
            std::fs::symlink_metadata(&backup)
                .unwrap()
                .file_type()
                .is_symlink(),
            "restore must leave the symlinked backup path untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_restore_update_backup_revalidates_symlinked_binary_at_restore_time() {
        let _guard = ApplyFailureFlagsGuard::lock();
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        let outside = dir.path().join("outside-active-binary");
        std::fs::write(&outside, b"outside-active").unwrap();
        symlink(&outside, &binary).unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"new"),
            backup_sha256: Some(sha256_bytes(b"old")),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Started,
            started_at_ms: Some(now_ms()),
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };

        let err = restore_update_backup(&marker)
            .expect_err("restore must reject symlinked binary destination at rename time");

        assert!(err.message.contains("not a no-follow regular file"));
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside-active");
        assert!(
            backup.exists(),
            "backup must remain available after refused restore"
        );
    }

    #[test]
    fn test_old_binary_cleanup_does_not_advance_pending_rollback_marker() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Pending,
                started_at_ms: None,
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        cleanup_old_binaries(dir.path());

        let marker = load_update_rollback_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.startup_state, UpdateRollbackStartupState::Pending);
        assert!(
            backup.exists(),
            "apply-side cleanup must not remove the active rollback backup"
        );
    }

    #[test]
    fn test_startup_old_binary_cleanup_protects_active_rollback_backup() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let active_backup = backup_path_for_binary(&exe);
        let stale_old = dir.path().join("cara.old");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&active_backup, b"rollback").unwrap();
        std::fs::write(&stale_old, b"stale").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), Some(&active_backup), None);

        assert!(
            active_backup.exists(),
            "startup cleanup must preserve the marker-protected rollback backup"
        );
        assert!(
            !stale_old.exists(),
            "startup cleanup should still remove unprotected old-binary siblings"
        );
    }

    #[test]
    fn test_startup_old_binary_cleanup_protects_backup_by_file_identity() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let active_backup = backup_path_for_binary(&exe);
        let stale_old = dir.path().join("cara.old");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&active_backup, b"rollback").unwrap();
        std::fs::write(&stale_old, b"stale").unwrap();
        let protected = dir.path().join(".").join("cara.bak");

        cleanup_bak_files_for_exe(&exe, dir.path(), Some(&protected), None);

        assert!(
            active_backup.exists(),
            "startup cleanup must compare protected rollback backups by file identity"
        );
        assert!(!stale_old.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_startup_old_binary_cleanup_protects_backup_via_symlinked_exe_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real_dir = root.path().join("private-var");
        let linked_dir = root.path().join("var");
        std::fs::create_dir_all(&real_dir).unwrap();
        symlink(&real_dir, &linked_dir).unwrap();
        let exe = real_dir.join("cara");
        let active_backup = real_dir.join("cara.bak");
        let stale_old = real_dir.join("cara.old");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&active_backup, b"rollback").unwrap();
        std::fs::write(&stale_old, b"stale").unwrap();
        let protected = linked_dir.join("cara.bak");

        cleanup_bak_files_for_exe(&exe, &real_dir, Some(&protected), None);

        assert!(
            active_backup.exists(),
            "protected rollback backup should match by file identity through symlinked parent dirs"
        );
        assert!(!stale_old.exists());
    }

    /// Regression for R58 H-UR2: the protected-backup identity must
    /// be captured ONCE at function entry and reused for every
    /// candidate comparison. The pre-fix loop re-stat'd the
    /// protected path on every candidate, so a transient I/O error
    /// on the protected path during one iteration would let the
    /// candidate-rejection collapse and reap the protected backup.
    ///
    /// We can't easily simulate a transient I/O error in a unit
    /// test, so this test pins the structural invariant by deleting
    /// the protected file BEFORE the loop runs and verifying the
    /// function rejects the cleanup (because identity could not be
    /// captured). Combined with the captured-identity match below,
    /// this proves identity is established up-front rather than
    /// re-derived per iteration.
    #[test]
    fn test_startup_old_binary_cleanup_aborts_when_protected_cannot_be_captured() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let cara_old = dir.path().join("cara.old");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&cara_old, b"stale").unwrap();
        // The "protected backup" path does NOT exist — the cleanup
        // must refuse to proceed rather than reaping `cara.old` on
        // the assumption that "no protected backup found = nothing
        // to protect."
        let missing_protected = dir.path().join("missing.bak");

        cleanup_bak_files_for_exe(&exe, dir.path(), Some(&missing_protected), None);

        assert!(
            cara_old.exists(),
            "cleanup must refuse to proceed when the protected backup identity cannot be captured"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_startup_old_binary_cleanup_captured_identity_matches_hardlink() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let protected = dir.path().join("cara.bak");
        // `hardlink_alias` is a second dirent pointing at the same
        // inode as `protected`. The cleanup loop should treat it as
        // identical-to-protected via the captured dev/ino and skip
        // it rather than reap it.
        let hardlink_alias = dir.path().join("cara.hardlink.bak");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&protected, b"rollback").unwrap();
        std::fs::hard_link(&protected, &hardlink_alias).unwrap();
        // Sanity: confirm the two paths share an inode.
        let protected_meta = std::fs::metadata(&protected).unwrap();
        let alias_meta = std::fs::metadata(&hardlink_alias).unwrap();
        assert_eq!(protected_meta.ino(), alias_meta.ino());

        cleanup_bak_files_for_exe(&exe, dir.path(), Some(&protected), None);

        assert!(
            protected.exists(),
            "protected rollback backup must survive cleanup"
        );
        assert!(
            hardlink_alias.exists(),
            "hardlink to protected backup must be identified by captured dev/ino and skipped"
        );
    }

    #[test]
    fn test_startup_old_binary_cleanup_preserves_side_by_side_daemon_backups() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let cara_backup = dir.path().join("cara.bak");
        let cara_old = dir.path().join("cara.old");
        let cara2_backup = dir.path().join("cara2.bak");
        let cara2_old = dir.path().join("cara2.old");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&cara_backup, b"old").unwrap();
        std::fs::write(&cara_old, b"older").unwrap();
        std::fs::write(&cara2_backup, b"other-old").unwrap();
        std::fs::write(&cara2_old, b"other-older").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), None, None);

        assert!(!cara_backup.exists());
        assert!(!cara_old.exists());
        assert!(
            cara2_backup.exists() && cara2_old.exists(),
            "cleanup for cara must not remove side-by-side cara2 rollback files"
        );
    }

    #[test]
    fn test_startup_old_binary_cleanup_matches_case_insensitive_suffixes() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("Cara");
        let backup = dir.path().join("cara.BAK");
        let old = dir.path().join("CARA.OLD");
        let other = dir.path().join("cara-helper.BAK");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        std::fs::write(&old, b"older").unwrap();
        std::fs::write(&other, b"other").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), None, None);

        assert!(
            !backup.exists() && !old.exists(),
            "case-insensitive filesystems should not strand rollback siblings"
        );
        assert!(
            other.exists(),
            "case-insensitive matching still scopes cleanup to this executable"
        );
    }

    #[test]
    fn test_startup_old_binary_cleanup_audits_reaped_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let backup = dir.path().join("cara.bak");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&backup, b"old").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), None, Some(state_dir.path()));

        assert!(!backup.exists());
        let audit = std::fs::read_to_string(state_dir.path().join("audit.jsonl"))
            .expect("stale backup cleanup must leave durable audit evidence");
        let entry: crate::logging::audit::AuditEntry =
            serde_json::from_str(audit.lines().next().expect("audit line")).unwrap();
        assert_eq!(entry.event, "update_rollback_backup_reaped");
        assert_eq!(
            entry.data["path"],
            serde_json::json!("<update-rollback-backup>/cara.bak")
        );
        let dir_text = dir.path().to_string_lossy().into_owned();
        assert!(
            !audit.contains(&dir_text),
            "rollback cleanup audit must not expose the executable directory path"
        );
    }

    #[tokio::test]
    async fn test_startup_old_binary_cleanup_durably_audits_with_initialized_writer() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        crate::logging::audit::AuditLog::init(state_dir.path().to_path_buf())
            .await
            .expect("audit init must succeed in this test fixture");
        let initialized_for_state_dir =
            crate::logging::audit::audit_blocking_or_enqueue_for_state_dir(
                state_dir.path().to_path_buf(),
                crate::logging::audit::AuditEvent::GatewayConnected {
                    gateway_id: "probe".into(),
                },
            )
            .map(|outcome| matches!(outcome, crate::logging::audit::AuditWriteOutcome::Enqueued))
            .unwrap_or(false);
        let exe = dir.path().join("cara");
        let backup = dir.path().join("cara.bak");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&backup, b"old").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), None, Some(state_dir.path()));

        assert!(
            !backup.exists(),
            "startup cleanup may block on durable audit evidence and then reap stale rollback backups"
        );
        let audit = std::fs::read_to_string(state_dir.path().join("audit.jsonl"))
            .expect("stale backup cleanup must leave durable audit evidence");
        assert!(
            audit.contains("update_rollback_backup_reaped"),
            "cleanup audit must be durable before deleting the backup"
        );
        if initialized_for_state_dir {
            assert!(
                audit.contains("<update-rollback-backup>/cara.bak"),
                "same-state-dir writer path must still use the redacted durable cleanup event"
            );
        }
    }

    #[test]
    fn test_startup_old_binary_cleanup_preserves_backup_when_audit_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir_parent = tempfile::tempdir().unwrap();
        let audit_state_dir = state_dir_parent.path().join("audit-state-file");
        std::fs::write(&audit_state_dir, b"not a directory").unwrap();
        let exe = dir.path().join("cara");
        let backup = dir.path().join("cara.bak");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&backup, b"old").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), None, Some(&audit_state_dir));

        assert!(
            backup.exists(),
            "startup cleanup must not delete rollback material when durable audit fails"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_startup_old_binary_cleanup_skips_when_protected_backup_is_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let stale_backup = dir.path().join("cara.bak");
        let protected_link = dir.path().join("protected.bak");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&stale_backup, b"stale").unwrap();
        symlink(&stale_backup, &protected_link).unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), Some(&protected_link), None);

        assert!(
            stale_backup.exists(),
            "a symlinked protected backup path must make cleanup fail closed before deleting real backups"
        );
        assert!(
            std::fs::symlink_metadata(&protected_link).is_ok(),
            "protected symlink itself is outside this cleanup scope"
        );
    }

    /// Regression for R58 M-UR5: `compute_sha256_no_follow` must
    /// refuse to traverse a symlink at the supplied path. Without
    /// this, an attacker who plants a symlink between the
    /// `validate_update_rollback_backup_path` symlink_metadata
    /// check and the hash could redirect the hash to a foreign
    /// target — letting the marker record an attacker-chosen
    /// `backup_sha256`.
    #[cfg(unix)]
    #[test]
    fn test_compute_sha256_no_follow_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("legitimate-binary");
        std::fs::write(&target, b"legitimate").unwrap();
        let link = dir.path().join("symlinked-backup");
        symlink(&target, &link).unwrap();

        // The plain `compute_sha256` follows symlinks and would
        // hash the target; the no-follow variant must refuse.
        let plain = compute_sha256(&link).expect("plain compute_sha256 follows symlink");
        assert_eq!(plain, compute_sha256(&target).unwrap());

        let err =
            compute_sha256_no_follow(&link).expect_err("no-follow hashing must refuse symlinks");
        assert!(
            err.message.contains("symlink") || err.message.contains("reparse"),
            "no-follow rejection must mention the symlink/reparse class: {err:?}"
        );
    }

    #[test]
    fn test_compute_sha256_no_follow_accepts_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("backup");
        std::fs::write(&regular, b"backup-content").unwrap();
        let hash = compute_sha256_no_follow(&regular)
            .expect("no-follow hashing must accept regular files");
        let plain = compute_sha256(&regular).expect("plain hash");
        assert_eq!(hash, plain, "no-follow + plain must agree on regular files");
    }

    #[cfg(unix)]
    #[test]
    fn test_persist_update_rollback_marker_rejects_symlinked_backup_path() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let real_backup = dir.path().join("cara.real.bak");
        let backup_link = dir.path().join("cara.bak");
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&real_backup, b"old").unwrap();
        symlink(&real_backup, &backup_link).unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.display().to_string(),
            backup_path: backup_link.display().to_string(),
            sha256: sha256_bytes(b"new"),
            backup_sha256: Some(sha256_bytes(b"old")),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Pending,
            started_at_ms: None,
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };

        let err = persist_update_rollback_marker(dir.path(), &marker)
            .expect_err("symlinked rollback backup path must not be persisted");

        assert!(
            err.message.contains("no-follow regular file"),
            "unexpected rollback marker error: {err:?}"
        );
        assert!(
            !update_rollback_marker_path(dir.path()).exists(),
            "rejected rollback markers must not leave marker material behind"
        );
    }

    /// Pins the forward-compat fallback for UpdateRollbackStartupState.
    /// An older binary reading a rollback marker written by a newer
    /// daemon (the precise scenario rollback exists to recover from)
    /// must NOT hard-error the marker parse, and must fall back to
    /// `RolledBack` (the safe default that does not re-trigger
    /// rollback against a newer binary the operator just installed).
    /// Mirrors test_deserialize_update_phase_unknown_value_is_treated_as_missing
    /// in audit.rs; the production code-comment explicitly claims this
    /// pattern but the test was missing.
    #[test]
    fn test_deserialize_update_rollback_marker_unknown_startup_state_falls_back_to_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let marker_path = update_rollback_marker_path(dir.path());
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        // Write a marker JSON with a future-introduced startup_state
        // wire value the older binary doesn't recognize.
        let raw = serde_json::json!({
            "binaryPath": dir.path().join("cara").display().to_string(),
            "backupPath": dir.path().join("cara.bak").display().to_string(),
            "sha256": sha256_bytes(b"new"),
            "appliedAtMs": now_ms(),
            "startupState": "future_state_added_in_v2",
        });
        std::fs::write(&marker_path, serde_json::to_vec(&raw).unwrap()).unwrap();
        // Need a regular file at backupPath so ensure_update_state_dir_secure
        // and downstream don't fail on missing-file checks.
        std::fs::write(dir.path().join("cara"), b"new").unwrap();
        std::fs::write(dir.path().join("cara.bak"), b"old").unwrap();

        let loaded = load_update_rollback_marker(dir.path())
            .expect("forward-compat: unknown startup_state must NOT hard-error the parse");
        let marker = loaded.expect("rollback marker must be present");
        assert_eq!(
            marker.startup_state,
            UpdateRollbackStartupState::RolledBack,
            "unknown startup_state must fall back to RolledBack (safe default that does not \
             re-trigger rollback against a newer binary the operator just installed)"
        );
    }

    /// Forward-compat: `UpdateTransaction.phase` must tolerate
    /// unknown wire values written by a newer daemon. The fail-safe
    /// fallback is `Failed` — an older binary reading a transaction
    /// it doesn't fully understand should treat the in-flight
    /// transaction as a non-resumable failure (operator intervention
    /// expected) rather than hard-error the parse and break
    /// `cara update install` entirely. Mirrors the existing
    /// `UpdateRollbackStartupState` and `UpdateStartupHealthFailure.phase`
    /// forward-compat patterns.
    #[test]
    fn test_update_transaction_phase_forward_compat_unknown_falls_back_to_failed() {
        let raw = serde_json::json!({
            "id": "txn-1",
            "version": "1.2.3",
            "assetName": "cara-linux",
            "state": "failed",
            "attempt": 1,
            "maxAttempts": 3,
            "startedAtMs": 0u64,
            "updatedAtMs": 0u64,
            "stagedPath": null,
            "bundlePath": null,
            "sha256": null,
            "lastError": null,
            "phase": "future_phase_added_in_v2",
            "retryable": false
        });
        let txn: UpdateTransaction = serde_json::from_value(raw)
            .expect("forward-compat: unknown phase must NOT hard-error the parse");
        assert_eq!(
            txn.phase,
            UpdatePhase::Failed,
            "unknown phase must fall back to Failed (fail-closed default)"
        );
    }

    /// Forward-compat regression: pins that an older binary reading a
    /// transaction.json written by a newer daemon does NOT hard-error
    /// when it encounters an unknown `state` value. Without this the
    /// downgrade path needs the operator to delete transaction.json by
    /// hand before `cara update install/resume` will run. Companion to
    /// the `UpdatePhase` test above; both close the same forward-compat
    /// hole on the same struct.
    #[test]
    fn test_update_transaction_state_forward_compat_unknown_falls_back_to_failed() {
        let raw = serde_json::json!({
            "id": "txn-1",
            "version": "1.2.3",
            "assetName": "cara-linux",
            "state": "future_state_added_in_v2",
            "attempt": 1,
            "maxAttempts": 3,
            "startedAtMs": 0u64,
            "updatedAtMs": 0u64,
            "stagedPath": null,
            "bundlePath": null,
            "sha256": null,
            "lastError": null,
            "phase": "failed",
            "retryable": false
        });
        let txn: UpdateTransaction = serde_json::from_value(raw)
            .expect("forward-compat: unknown transaction state must NOT hard-error the parse");
        assert_eq!(
            txn.state,
            UpdateTransactionState::Failed,
            "unknown transaction state must fall back to Failed (fail-closed default)"
        );
    }

    /// Round-trip pin: known transaction state wire names still parse
    /// to their respective variants when read through the forward-compat
    /// deserializer (i.e. tolerance does NOT silently downgrade known
    /// states to `Failed`).
    #[test]
    fn test_update_transaction_state_forward_compat_known_states_roundtrip() {
        for (state, wire) in [
            (UpdateTransactionState::InProgress, "in_progress"),
            (UpdateTransactionState::Applied, "applied"),
            (UpdateTransactionState::Failed, "failed"),
        ] {
            let raw = serde_json::json!({
                "id": "txn-1",
                "version": "1.2.3",
                "assetName": "cara-linux",
                "state": wire,
                "attempt": 1,
                "maxAttempts": 3,
                "startedAtMs": 0u64,
                "updatedAtMs": 0u64,
                "stagedPath": null,
                "bundlePath": null,
                "sha256": null,
                "lastError": null,
                "phase": "created",
                "retryable": false
            });
            let txn: UpdateTransaction =
                serde_json::from_value(raw).expect("known state must parse cleanly");
            assert_eq!(txn.state, state, "known wire name `{wire}` must round-trip");
        }
    }

    /// B120 regression: `UpdateTransaction.extra` flatten capture
    /// preserves unknown fields across RMW so an older binary's
    /// `load_update_transaction` -> mutate -> persist roundtrip
    /// does not silently drop newer-binary fields (apply telemetry,
    /// retry counters, new metadata). Without this, an operator who
    /// downgrades after an upgrade-incident loses every newer-binary
    /// field on the first older-binary persist.
    #[test]
    fn test_update_transaction_extra_preserves_unknown_fields_on_roundtrip() {
        let raw = serde_json::json!({
            "id": "txn-1",
            "version": "1.2.3",
            "assetName": "cara-linux",
            "state": "in_progress",
            "attempt": 1,
            "maxAttempts": 3,
            "startedAtMs": 0u64,
            "updatedAtMs": 0u64,
            "stagedPath": null,
            "bundlePath": null,
            "sha256": null,
            "lastError": null,
            "phase": "created",
            "retryable": false,
            // Forward-compat fields a newer daemon might write:
            "applyTelemetry": { "hostname": "host-1", "duration_ms": 42 },
            "retryWindowMs": 60000u64
        });
        let txn: UpdateTransaction =
            serde_json::from_value(raw.clone()).expect("must parse with unknown fields");
        assert_eq!(txn.extra.len(), 2);
        assert_eq!(
            txn.extra.get("applyTelemetry"),
            Some(&serde_json::json!({ "hostname": "host-1", "duration_ms": 42 }))
        );
        assert_eq!(
            txn.extra.get("retryWindowMs"),
            Some(&serde_json::json!(60000u64))
        );
        // Round-trip: serialize the parsed struct, parse again, fields must remain.
        let reserialized: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&txn).unwrap()).unwrap();
        assert_eq!(
            reserialized.get("applyTelemetry"),
            Some(&serde_json::json!({ "hostname": "host-1", "duration_ms": 42 })),
            "unknown applyTelemetry field must survive RMW"
        );
        assert_eq!(
            reserialized.get("retryWindowMs"),
            Some(&serde_json::json!(60000u64)),
            "unknown retryWindowMs field must survive RMW"
        );
    }

    /// B120 regression: same shape for `UpdateRollbackMarker.extra`.
    /// An operator downgrade after a bad upgrade is the precise
    /// scenario the rollback marker exists to recover; silently
    /// dropping newer-binary fields on the first older-binary
    /// rewrite loses post-downgrade incident-response evidence.
    #[test]
    fn test_update_rollback_marker_extra_preserves_unknown_fields_on_roundtrip() {
        let raw = serde_json::json!({
            "binaryPath": "/usr/local/bin/cara",
            "backupPath": "/usr/local/bin/cara.bak",
            "sha256": "abc123",
            "appliedAtMs": 0u64,
            "startupState": "pending",
            // Forward-compat field a newer daemon might write:
            "downgradeAuditTrail": "ci-job-12345"
        });
        let marker: UpdateRollbackMarker =
            serde_json::from_value(raw).expect("must parse with unknown fields");
        assert_eq!(marker.extra.len(), 1);
        assert_eq!(
            marker.extra.get("downgradeAuditTrail"),
            Some(&serde_json::json!("ci-job-12345"))
        );
        let reserialized: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&marker).unwrap()).unwrap();
        assert_eq!(
            reserialized.get("downgradeAuditTrail"),
            Some(&serde_json::json!("ci-job-12345")),
            "unknown downgradeAuditTrail field must survive RMW"
        );
    }

    /// B120 regression: `UpdateStartupEvidenceKind` forward-compat
    /// deserializer falls back to `UpdateHealthyMarkerFailed` on
    /// unknown wire values. Without this, `load_update_startup_health_failure`
    /// hard-errors on a newer-binary's startup-health-failure file,
    /// blocking `mark_pending_update_healthy` / `cara update install`
    /// resume — the precise downgrade-recovery scenario the rollback
    /// mechanism exists to handle.
    #[test]
    fn test_update_startup_evidence_kind_forward_compat_unknown_falls_back() {
        let raw = serde_json::json!({
            "event": "future_evidence_kind_added_in_v2",
            "failedAtMs": 0u64,
            "message": "future evidence",
            "retryable": false
        });
        let failure: UpdateStartupHealthFailure =
            serde_json::from_value(raw).expect("unknown evidence kind must NOT hard-error");
        assert_eq!(
            failure.event,
            UpdateStartupEvidenceKind::UpdateHealthyMarkerFailed,
            "unknown evidence kind must fall back to UpdateHealthyMarkerFailed (conservative default)"
        );
    }

    /// Round-trip pin: known evidence kinds still parse to their
    /// respective variants through the forward-compat deserializer.
    #[test]
    fn test_update_startup_evidence_kind_forward_compat_known_kinds_roundtrip() {
        for (kind, wire) in UpdateStartupEvidenceKind::ALL {
            let raw = serde_json::json!({
                "event": wire,
                "failedAtMs": 0u64,
                "message": "msg",
                "retryable": false
            });
            let failure: UpdateStartupHealthFailure =
                serde_json::from_value(raw).expect("known kind must parse cleanly");
            assert_eq!(failure.event, *kind, "wire `{wire}` must round-trip");
        }
    }

    #[test]
    fn test_apply_result_without_backup_does_not_persist_fake_rollback_marker() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        std::fs::write(&binary, b"new").unwrap();
        let apply_result = ApplyResult {
            applied: true,
            sha256: sha256_bytes(b"new"),
            binary_path: binary.to_string_lossy().into_owned(),
        };

        persist_recoverable_rollback_marker_for_apply_result(dir.path(), &apply_result).unwrap();

        assert!(
            load_update_rollback_marker(dir.path()).unwrap().is_none(),
            "apply evidence without a backup must not create a fake recoverable rollback marker"
        );
    }

    #[test]
    fn test_apply_result_with_backup_persists_recoverable_rollback_marker() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let apply_result = ApplyResult {
            applied: true,
            sha256: sha256_bytes(b"new"),
            binary_path: binary.to_string_lossy().into_owned(),
        };

        persist_recoverable_rollback_marker_for_apply_result(dir.path(), &apply_result).unwrap();

        let marker = load_update_rollback_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.backup_path, backup.to_string_lossy());
        assert_eq!(
            marker.backup_sha256.as_deref(),
            Some(sha256_bytes(b"old").as_str())
        );
        assert_eq!(marker.startup_state, UpdateRollbackStartupState::Pending);
    }

    #[test]
    fn test_apply_result_marker_failure_is_non_retryable_applied_phase() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let apply_result = ApplyResult {
            applied: true,
            sha256: sha256_bytes(b"new"),
            binary_path: binary.to_string_lossy().into_owned(),
        };

        _guard.force_rollback_marker_persist_failure();
        let err = persist_recoverable_rollback_marker_after_apply(dir.path(), &apply_result)
            .expect_err("post-apply marker persistence failure must surface");

        assert_eq!(err.phase, Some(UpdatePhase::Applied));
        assert!(!err.retryable);
        assert!(err
            .message
            .contains("rollback safety marker was not persisted"));
        assert!(backup.exists());
        assert!(load_update_rollback_marker(dir.path()).unwrap().is_none());
    }

    #[test]
    fn test_apply_marker_failure_records_non_applied_transaction_failure() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let apply_result = ApplyResult {
            applied: true,
            sha256: sha256_bytes(b"new"),
            binary_path: binary.to_string_lossy().into_owned(),
        };
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        tx.state = UpdateTransactionState::InProgress;
        tx.phase = UpdatePhase::Applying;
        persist_update_transaction(dir.path(), &tx).unwrap();

        _guard.force_rollback_marker_persist_failure();
        let err = persist_recoverable_rollback_marker_after_apply(dir.path(), &apply_result)
            .expect_err("post-apply marker persistence failure must surface");
        record_failure(dir.path(), &mut tx, &err).unwrap();

        let failed = load_update_transaction(dir.path()).unwrap().unwrap();
        assert_eq!(failed.state, UpdateTransactionState::Failed);
        assert_eq!(failed.phase, UpdatePhase::Failed);
        assert!(!failed.retryable);
        assert_ne!(failed.state, UpdateTransactionState::Applied);
        assert_eq!(err.phase, Some(UpdatePhase::Applied));
    }

    #[test]
    fn test_mark_pending_update_healthy_only_clears_started_marker() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Pending,
                started_at_ms: None,
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        mark_pending_update_healthy(dir.path()).unwrap();
        assert!(
            backup.exists(),
            "Pending backup must remain until a real startup"
        );
        assert_eq!(
            load_update_rollback_marker(dir.path())
                .unwrap()
                .unwrap()
                .startup_state,
            UpdateRollbackStartupState::Pending
        );

        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::RolledBack,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: Some(now_ms()),
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        mark_pending_update_healthy(dir.path()).unwrap();
        assert!(
            load_update_rollback_marker(dir.path()).unwrap().is_some(),
            "RolledBack evidence must survive healthy-marker cleanup"
        );
    }

    #[test]
    fn test_mark_pending_update_healthy_failure_records_status_evidence() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        _guard.force_rollback_marker_clear_failure();
        let err = mark_pending_update_healthy(dir.path())
            .expect_err("healthy marker clear failure must be surfaced");

        let error = match err {
            UpdateHealthyMarkerError::Marker {
                error,
                evidence: Some(_),
            } => error,
            other => panic!("expected marker failure with evidence, got {other:?}"),
        };
        assert_eq!(error.message, "forced rollback marker clear failure");
        let failure = load_update_startup_health_failure(dir.path())
            .unwrap()
            .expect("failure evidence must be durable");
        assert_eq!(
            failure.event,
            UpdateStartupEvidenceKind::UpdateHealthyMarkerFailed
        );
        let wire = serde_json::to_value(&failure).unwrap();
        assert_eq!(wire["event"], "update_healthy_marker_failed");
        assert_eq!(failure.message, "forced rollback marker clear failure");
        assert!(failure.retryable);
        assert!(
            backup.exists(),
            "rollback backup must not be garbage-collected until marker removal is durable"
        );
    }

    /// Regression for R58 H-UR3: when the rollback marker's
    /// post-unlink fsync fails (e.g., transient ENOSPC on the
    /// parent dir), the function must NOT propagate an Err. The
    /// `remove_file` syscall already succeeded — the marker is gone
    /// from the in-memory dirent — and propagating Err would cause
    /// the outer wrapper to persist failure evidence for a healthy
    /// update. A retry would observe the marker as NotFound and
    /// short-circuit to Ok without re-fsyncing, so the "retryable"
    /// classification is misleading.
    #[test]
    fn test_mark_pending_update_healthy_tolerates_marker_fsync_failure() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        _guard.force_rollback_marker_fsync_failure();
        // The function must return Ok despite the fsync failure.
        // Returning Err would persist `UpdateHealthyMarkerFailed`
        // evidence for a healthy update and a power loss before the
        // dirent change durably commits could let the next boot
        // see the marker again, triggering a false-positive
        // rollback that undoes the healthy update.
        mark_pending_update_healthy(dir.path())
            .expect("post-unlink fsync failure must NOT propagate as a healthy-marker error");

        assert!(
            load_update_rollback_marker(dir.path()).unwrap().is_none(),
            "marker must be gone from in-memory state after unlink"
        );
        assert!(
            !backup.exists(),
            "backup must be removed after the marker clear succeeds — the fsync failure on the \
             marker's parent dir does not block the backup-remove step"
        );
        assert!(
            load_update_startup_health_failure(dir.path())
                .unwrap()
                .is_none(),
            "no failure evidence must be persisted: the marker clear is semantically successful"
        );
    }

    #[test]
    fn test_update_tmp_file_creation_is_no_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let tmp_path = dir.path().join("rollback.json.tmp");
        std::fs::write(&tmp_path, b"preexisting").unwrap();

        let err = create_update_tmp_file_owner_only(&tmp_path)
            .expect_err("pre-existing update temp file must not be opened or truncated");

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&tmp_path).unwrap(), b"preexisting");
    }

    #[test]
    fn test_update_marker_and_evidence_writes_ignore_stale_fixed_tmp_names() {
        let dir = tempfile::tempdir().unwrap();
        let updates_dir = dir.path().join("updates");
        std::fs::create_dir_all(&updates_dir).unwrap();
        let old_rollback_tmp = updates_dir.join("rollback.json.tmp");
        let old_evidence_tmp = updates_dir.join("startup_health_failure.json.tmp");
        std::fs::write(&old_rollback_tmp, b"stale rollback tmp").unwrap();
        std::fs::write(&old_evidence_tmp, b"stale evidence tmp").unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();

        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Pending,
                started_at_ms: None,
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        persist_update_startup_health_failure(
            dir.path(),
            &UpdateError::retryable(Some(UpdatePhase::Applied), "startup failed"),
        )
        .unwrap();

        assert!(load_update_rollback_marker(dir.path()).unwrap().is_some());
        assert!(load_update_startup_health_failure(dir.path())
            .unwrap()
            .is_some());
        assert_eq!(
            std::fs::read(&old_rollback_tmp).unwrap(),
            b"stale rollback tmp"
        );
        assert_eq!(
            std::fs::read(&old_evidence_tmp).unwrap(),
            b"stale evidence tmp"
        );
    }

    #[test]
    fn test_update_startup_health_failure_evidence_retained_with_pending_rollback_marker() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let stale = UpdateError::retryable(
            Some(UpdatePhase::Applied),
            "old startup health failure evidence",
        );
        persist_update_startup_health_failure(dir.path(), &stale).unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Pending,
                started_at_ms: None,
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        let evidence_path = update_startup_health_failure_path(dir.path());
        let stale_time = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(&evidence_path, stale_time).unwrap();

        cleanup_stale_staged_updates(dir.path());

        assert!(
            evidence_path.exists(),
            "startup health failure evidence must survive while rollback marker material is protected"
        );
    }

    /// Regression for R58 M-UR4: a `RolledBack` marker means the
    /// rollback completed and the operator is on the prior binary;
    /// the health-failure evidence must NOT be preserved
    /// indefinitely under this terminal phase. Pre-fix code matched
    /// `Ok(Some(_))` regardless of `startup_state`, so the evidence
    /// accumulated for years.
    #[test]
    fn test_update_startup_health_failure_evidence_ages_out_after_rollback_completes() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let stale = UpdateError::retryable(
            Some(UpdatePhase::Applied),
            "old startup health failure evidence",
        );
        persist_update_startup_health_failure(dir.path(), &stale).unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::RolledBack,
                started_at_ms: Some(now_ms().saturating_sub(2000)),
                rolled_back_at_ms: Some(now_ms().saturating_sub(1000)),
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        let evidence_path = update_startup_health_failure_path(dir.path());
        let stale_time = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(&evidence_path, stale_time).unwrap();

        cleanup_stale_staged_updates(dir.path());

        assert!(
            !evidence_path.exists(),
            "RolledBack marker means the rollback cycle is complete — health-failure evidence must age out, not accumulate forever"
        );
    }

    #[test]
    fn test_update_startup_health_failure_evidence_ages_out_without_rollback_marker() {
        let dir = tempfile::tempdir().unwrap();
        let stale = UpdateError::retryable(
            Some(UpdatePhase::Applied),
            "old startup health failure evidence",
        );
        persist_update_startup_health_failure(dir.path(), &stale).unwrap();
        let evidence_path = update_startup_health_failure_path(dir.path());
        let stale_time = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(&evidence_path, stale_time).unwrap();

        cleanup_stale_staged_updates(dir.path());

        assert!(
            !evidence_path.exists(),
            "stale startup health failure evidence should age out after rollback marker cleanup"
        );
    }

    #[test]
    fn test_stale_update_tmp_files_age_out_but_fresh_tmp_files_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let updates_dir = dir.path().join("updates");
        std::fs::create_dir_all(&updates_dir).unwrap();
        let stale_tmp = updates_dir.join("rollback.json.tmp");
        let fresh_tmp = updates_dir.join("startup_health_failure.json.tmp");
        std::fs::write(&stale_tmp, b"stale tmp").unwrap();
        std::fs::write(&fresh_tmp, b"fresh tmp").unwrap();
        let stale_time = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(&stale_tmp, stale_time).unwrap();

        cleanup_stale_staged_updates(dir.path());

        assert!(!stale_tmp.exists(), "stale update temp file must age out");
        assert!(
            fresh_tmp.exists(),
            "fresh update temp file must be preserved"
        );
    }

    #[test]
    fn test_stale_update_cleanup_preserves_active_staged_and_bundle_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        let staged = update_staging_path(dir.path(), "0.1.0");
        let bundle = update_bundle_path(dir.path(), "0.1.0");
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"staged").unwrap();
        std::fs::write(&bundle, b"bundle").unwrap();
        tx.staged_path = Some(staged.to_string_lossy().into_owned());
        tx.bundle_path = Some(bundle.to_string_lossy().into_owned());
        persist_update_transaction(dir.path(), &tx).unwrap();
        let stale_time = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(&staged, stale_time).unwrap();
        filetime::set_file_mtime(&bundle, stale_time).unwrap();

        cleanup_stale_staged_updates(dir.path());

        assert!(staged.exists(), "active staged_path must not be collected");
        assert!(bundle.exists(), "active bundle_path must not be collected");
    }

    #[test]
    fn test_stale_update_cleanup_fails_closed_on_unreadable_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let updates_dir = dir.path().join("updates");
        std::fs::create_dir_all(&updates_dir).unwrap();
        std::fs::write(update_transaction_path(dir.path()), b"{not-json").unwrap();
        let stale_tmp = updates_dir.join("orphan.tmp");
        std::fs::write(&stale_tmp, b"stale").unwrap();
        let stale_time = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_file_mtime(&stale_tmp, stale_time).unwrap();

        cleanup_stale_staged_updates(dir.path());

        assert!(
            stale_tmp.exists(),
            "cleanup must preserve update files when transaction ownership is unreadable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_transaction_path_validation_accepts_symlinked_state_dir() {
        use std::os::unix::fs::symlink;

        let real = tempfile::tempdir().unwrap();
        let links = tempfile::tempdir().unwrap();
        let linked_state = links.path().join("state-link");
        symlink(real.path(), &linked_state).unwrap();
        let staged_via_link = update_staging_path(&linked_state, "0.1.0");
        let staged_real = update_staging_path(real.path(), "0.1.0");
        std::fs::create_dir_all(staged_real.parent().unwrap()).unwrap();
        std::fs::write(&staged_real, b"staged").unwrap();

        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        tx.staged_path = Some(staged_via_link.to_string_lossy().into_owned());
        let payload = serde_json::to_vec_pretty(&tx).unwrap();
        std::fs::write(update_transaction_path(real.path()), payload).unwrap();

        let loaded = load_update_transaction(real.path())
            .expect("symlinked state-dir transaction path should validate")
            .expect("transaction present");
        assert_eq!(loaded.staged_path, tx.staged_path);
    }

    #[test]
    fn test_update_startup_evidence_kind_wire_names_are_exhaustive() {
        for (kind, wire) in UpdateStartupEvidenceKind::ALL {
            assert_eq!(kind.as_str(), *wire);
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::String((*wire).to_string())
            );
            assert_eq!(
                serde_json::from_value::<UpdateStartupEvidenceKind>(serde_json::Value::String(
                    (*wire).to_string()
                ))
                .unwrap(),
                *kind
            );
        }
    }

    #[test]
    fn test_update_phase_wire_names_are_exhaustive() {
        for (phase, wire) in UpdatePhase::ALL {
            assert_eq!(phase.as_str(), *wire);
            assert_eq!(
                serde_json::to_value(phase).unwrap(),
                serde_json::Value::String((*wire).to_string())
            );
            assert_eq!(
                serde_json::from_value::<UpdatePhase>(serde_json::Value::String(
                    (*wire).to_string()
                ))
                .unwrap(),
                *phase
            );
        }
    }

    #[test]
    fn test_update_rollback_startup_state_wire_names_are_exhaustive() {
        for (state, wire) in UpdateRollbackStartupState::ALL {
            assert_eq!(state.as_str(), *wire);
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                serde_json::Value::String((*wire).to_string())
            );
            assert_eq!(
                serde_json::from_value::<UpdateRollbackStartupState>(serde_json::Value::String(
                    (*wire).to_string()
                ))
                .unwrap(),
                *state
            );
        }
    }

    #[test]
    fn test_mark_pending_update_healthy_success_clears_status_evidence() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let stale = UpdateError::retryable(
            Some(UpdatePhase::Applied),
            "previous healthy-marker failure",
        );
        persist_update_startup_health_failure(dir.path(), &stale).unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        mark_pending_update_healthy(dir.path()).unwrap();

        assert!(load_update_startup_health_failure(dir.path())
            .unwrap()
            .is_none());
        assert!(load_update_rollback_marker(dir.path()).unwrap().is_none());
    }

    #[test]
    fn test_startup_cleanup_reconciles_backup_orphaned_after_marker_clear() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        _guard.force_rollback_backup_remove_failure();
        let err = mark_pending_update_healthy(dir.path())
            .expect_err("backup remove failure after marker clear must be surfaced");

        match err {
            UpdateHealthyMarkerError::Marker { error, evidence } => {
                assert!(
                    error
                        .message
                        .contains("forced update rollback backup removal failure"),
                    "unexpected healthy-marker error: {error:?}"
                );
                assert!(evidence.is_some(), "failure evidence should be persisted");
            }
            other => panic!("expected marker failure, got {other:?}"),
        }
        assert!(
            load_update_rollback_marker(dir.path()).unwrap().is_none(),
            "marker clear succeeded before backup cleanup failed"
        );
        assert!(
            backup.exists(),
            "failed backup removal leaves orphaned backup"
        );

        cleanup_bak_files_for_exe(&binary, dir.path(), None, None);

        assert!(
            !backup.exists(),
            "startup sibling cleanup must reconcile backup orphaned after marker clear"
        );
    }

    #[test]
    fn test_mark_pending_update_healthy_missing_backup_still_clears_marker() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        persist_update_startup_health_failure(
            dir.path(),
            &UpdateError::retryable(Some(UpdatePhase::Applied), "previous cleanup failure"),
        )
        .unwrap();
        let malformed_marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"new"),
            backup_sha256: Some(sha256_bytes(b"old")),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Started,
            started_at_ms: Some(now_ms().saturating_sub(1000)),
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };
        std::fs::write(
            update_rollback_marker_path(dir.path()),
            serde_json::to_vec_pretty(&malformed_marker).unwrap(),
        )
        .unwrap();

        mark_pending_update_healthy(dir.path()).unwrap();

        assert!(!backup.exists());
        assert!(load_update_rollback_marker(dir.path()).unwrap().is_none());
        assert!(load_update_startup_health_failure(dir.path())
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_mark_pending_update_healthy_clears_stale_evidence_without_marker() {
        let dir = tempfile::tempdir().unwrap();
        persist_update_startup_health_failure(
            dir.path(),
            &UpdateError::retryable(Some(UpdatePhase::Applied), "stale startup failure"),
        )
        .unwrap();

        mark_pending_update_healthy(dir.path()).unwrap();

        assert!(load_update_startup_health_failure(dir.path())
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_mark_pending_update_healthy_cleanup_failure_is_separate() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();
        std::fs::create_dir_all(update_startup_health_failure_path(dir.path())).unwrap();

        let err = mark_pending_update_healthy(dir.path())
            .expect_err("evidence cleanup failure must be surfaced separately");

        match err {
            UpdateHealthyMarkerError::EvidenceCleanup(error) => assert!(error
                .message
                .contains("failed to remove update startup health failure")),
            other => panic!("expected evidence cleanup failure, got {other:?}"),
        }
        assert!(
            !backup.exists(),
            "rollback backup should already be cleared"
        );
        assert!(load_update_rollback_marker(dir.path()).unwrap().is_none());
    }

    #[test]
    fn test_started_update_startup_restores_backup() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"new").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        persist_update_rollback_marker(
            dir.path(),
            &UpdateRollbackMarker {
                binary_path: binary.to_string_lossy().into_owned(),
                backup_path: backup.to_string_lossy().into_owned(),
                sha256: sha256_bytes(b"new"),
                backup_sha256: Some(sha256_bytes(b"old")),
                applied_at_ms: now_ms(),
                startup_state: UpdateRollbackStartupState::Started,
                started_at_ms: Some(now_ms().saturating_sub(1000)),
                rolled_back_at_ms: None,
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        let protected = begin_pending_update_startup(dir.path()).unwrap();
        assert!(protected.is_none());
        assert_eq!(std::fs::read(&binary).unwrap(), b"old");
        assert!(!backup.exists());
        let marker = load_update_rollback_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.startup_state, UpdateRollbackStartupState::RolledBack);
        assert!(marker.rolled_back_at_ms.is_some());
    }

    #[test]
    fn test_started_update_startup_recovers_after_backup_already_consumed() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"old").unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"new"),
            backup_sha256: Some(sha256_bytes(b"old")),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Started,
            started_at_ms: Some(now_ms().saturating_sub(1000)),
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };
        std::fs::create_dir_all(update_rollback_marker_path(dir.path()).parent().unwrap()).unwrap();
        std::fs::write(
            update_rollback_marker_path(dir.path()),
            serde_json::to_vec_pretty(&marker).unwrap(),
        )
        .unwrap();

        let protected = begin_pending_update_startup(dir.path()).unwrap();

        assert!(protected.is_none());
        assert_eq!(std::fs::read(&binary).unwrap(), b"old");
        let marker = load_update_rollback_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.startup_state, UpdateRollbackStartupState::RolledBack);
        assert!(marker.rolled_back_at_ms.is_some());
    }

    #[test]
    fn test_started_update_startup_missing_backup_rejects_unbound_binary_hash() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&binary, b"attacker-replacement").unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"new"),
            backup_sha256: Some(sha256_bytes(b"old")),
            applied_at_ms: now_ms(),
            startup_state: UpdateRollbackStartupState::Started,
            started_at_ms: Some(now_ms().saturating_sub(1000)),
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };
        std::fs::create_dir_all(update_rollback_marker_path(dir.path()).parent().unwrap()).unwrap();
        std::fs::write(
            update_rollback_marker_path(dir.path()),
            serde_json::to_vec_pretty(&marker).unwrap(),
        )
        .unwrap();

        let err = begin_pending_update_startup(dir.path())
            .expect_err("missing backup cannot be treated as consumed by any non-new binary hash");

        assert!(
            err.message.contains("backup") && err.message.contains("missing"),
            "unexpected rollback error: {err:?}"
        );
        let marker = load_update_rollback_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.startup_state, UpdateRollbackStartupState::Started);
    }

    #[test]
    fn test_old_binary_cleanup_preserves_unrelated_backup_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cara");
        let cara_backup = dir.path().join("cara.bak");
        let cara_old = dir.path().join("cara.old");
        let other_backup = dir.path().join("other-tool.bak");
        let nested_name_backup = dir.path().join("cara-helper.bak");
        std::fs::write(&exe, b"active").unwrap();
        std::fs::write(&cara_backup, b"old").unwrap();
        std::fs::write(&cara_old, b"older").unwrap();
        std::fs::write(&other_backup, b"unrelated").unwrap();
        std::fs::write(&nested_name_backup, b"unrelated").unwrap();

        cleanup_bak_files_for_exe(&exe, dir.path(), None, None);

        assert!(!cara_backup.exists());
        assert!(!cara_old.exists());
        assert!(other_backup.exists());
        assert!(nested_name_backup.exists());
    }

    #[test]
    fn test_update_transaction_lock_is_inter_process() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = update_lock_path(dir.path());
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }

        let first = crate::sessions::file_lock::FileLock::try_acquire(&lock_path)
            .unwrap()
            .expect("first lock acquisition succeeds");
        assert!(
            crate::sessions::file_lock::FileLock::try_acquire(&lock_path)
                .unwrap()
                .is_none(),
            "second acquisition must contend on the same update transaction lock"
        );
        drop(first);
        assert!(
            crate::sessions::file_lock::FileLock::try_acquire(&lock_path)
                .unwrap()
                .is_some(),
            "lock is released when the update guard drops"
        );
    }

    #[test]
    fn test_load_transaction_invalid_json_is_non_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let tx_path = update_transaction_path(dir.path());
        std::fs::create_dir_all(tx_path.parent().unwrap()).unwrap();
        std::fs::write(&tx_path, b"{not-valid-json").unwrap();
        let err =
            load_update_transaction(dir.path()).expect_err("invalid transaction JSON must fail");
        assert!(!err.retryable);
        assert!(err.message.contains("parse update transaction"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_apply_staged_update_success_for_paths() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let current = dir.path().join("cara");
        std::fs::write(&staged, b"new-binary").unwrap();
        std::fs::write(&current, b"old-binary").unwrap();

        let result =
            apply_staged_update_at_paths(&staged, &current, None).expect("apply should succeed");
        assert!(result.applied);
        assert_eq!(result.binary_path, current.to_string_lossy());
        assert_eq!(std::fs::read(&current).unwrap(), b"new-binary");
        assert_eq!(
            std::fs::read(backup_path_for_binary(&current)).unwrap(),
            b"old-binary"
        );
    }

    /// Pin the Batch 59 TOCTOU fix: `apply_staged_update_at_paths` opens
    /// the staged binary with `O_NOFOLLOW` and refuses to apply if the
    /// path is a symlink. Without this, a same-uid attacker who can
    /// briefly plant a symlink in `state_dir/updates/` between sigstore
    /// verify and the rename-and-copy gets arbitrary bytes copied into
    /// the daemon's live cara binary.
    #[cfg(unix)]
    #[test]
    fn test_apply_staged_update_refuses_symlinked_staged_path() {
        use std::os::unix::fs as unix_fs;
        let dir = tempfile::tempdir().unwrap();
        // Real legitimate-looking binary content.
        let target = dir.path().join("attacker-controlled");
        std::fs::write(&target, b"attacker-bytes").unwrap();
        // Staged path is a symlink pointing at attacker target.
        let staged = dir.path().join("staged");
        unix_fs::symlink(&target, &staged).unwrap();
        // Live binary path.
        let current = dir.path().join("cara");
        std::fs::write(&current, b"old-binary").unwrap();

        let err = apply_staged_update_at_paths(&staged, &current, None)
            .expect_err("symlinked staged path must be refused");
        // O_NOFOLLOW makes the open() itself fail with ELOOP on most
        // platforms ("Too many levels of symbolic links"); on the few
        // platforms where O_NOFOLLOW is a no-op the post-open
        // metadata file-type check fires instead.
        assert!(
            err.message.contains("symlink")
                || err.message.contains("regular file")
                || err.message.contains("symbolic link")
                || err.message.contains("os error 62"),
            "expected symlink/regular-file rejection, got: {}",
            err.message
        );
        // Live binary must NOT have been touched.
        assert_eq!(
            std::fs::read(&current).unwrap(),
            b"old-binary",
            "live binary must remain unchanged when staged path is a symlink"
        );
    }

    /// Pin Batch 71 Critical #1: apply refuses to copy a staged file
    /// whose actual content hash does not match `expected_hash`. This
    /// closes the verify→apply TOCTOU where a same-uid attacker swaps
    /// the staged dirent between the prior verify pass and the apply.
    #[cfg(unix)]
    #[test]
    fn test_apply_staged_update_refuses_when_fd_hash_mismatches_expected() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let current = dir.path().join("cara");
        std::fs::write(&staged, b"swapped-by-attacker").unwrap();
        std::fs::write(&current, b"old-binary").unwrap();
        let claimed_hash = sha256_bytes(b"what-verify-saw");

        let err = apply_staged_update_at_paths(&staged, &current, Some(&claimed_hash))
            .expect_err("hash mismatch must refuse the apply");
        assert!(
            err.message.contains("changed between verify and apply"),
            "expected verify→apply TOCTOU error, got: {}",
            err.message
        );
        assert_eq!(
            std::fs::read(&current).unwrap(),
            b"old-binary",
            "live binary must remain untouched on hash mismatch"
        );
    }

    /// Pin Batch 71 Critical #2: rollback restore refuses to copy
    /// backup bytes whose actual content hash does not match
    /// `marker.backup_sha256`. Same-uid attacker who swaps the backup
    /// dirent between apply-time hash recording and restore time
    /// cannot smuggle attacker-chosen bytes over the live cara binary.
    #[cfg(unix)]
    #[test]
    fn test_restore_update_backup_refuses_on_backup_hash_mismatch() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&backup, b"attacker-swapped-bytes").unwrap();
        std::fs::write(&binary, b"current").unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"current"),
            backup_sha256: Some(sha256_bytes(b"original-backup-bytes")),
            applied_at_ms: 0,
            startup_state: UpdateRollbackStartupState::Pending,
            started_at_ms: None,
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };
        let err = restore_update_backup(&marker)
            .expect_err("backup hash mismatch must refuse the restore");
        assert!(
            err.message.contains("does not match marker-recorded"),
            "expected backup-hash-mismatch error, got: {}",
            err.message
        );
        assert_eq!(
            std::fs::read(&binary).unwrap(),
            b"current",
            "live binary must remain untouched on backup hash mismatch"
        );
    }

    /// Pin Batch 71: rollback refuses unverified backups (older
    /// markers with `backup_sha256 == None`).
    #[cfg(unix)]
    #[test]
    fn test_restore_update_backup_refuses_when_marker_has_no_backup_sha256() {
        let _guard = ApplyFailureFlagsGuard::lock();
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("cara");
        let backup = backup_path_for_binary(&binary);
        std::fs::write(&backup, b"backup-bytes").unwrap();
        std::fs::write(&binary, b"current").unwrap();
        let marker = UpdateRollbackMarker {
            binary_path: binary.to_string_lossy().into_owned(),
            backup_path: backup.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"current"),
            backup_sha256: None,
            applied_at_ms: 0,
            startup_state: UpdateRollbackStartupState::Pending,
            started_at_ms: None,
            rolled_back_at_ms: None,
            extra: BTreeMap::new(),
        };
        let err = restore_update_backup(&marker)
            .expect_err("missing backup_sha256 must refuse the restore");
        assert!(
            err.message.contains("missing backup_sha256"),
            "expected unverified-backup error, got: {}",
            err.message
        );
        assert_eq!(
            std::fs::read(&binary).unwrap(),
            b"current",
            "live binary must remain untouched"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn test_apply_staged_update_copy_failure_restores_original() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let current = dir.path().join("cara");
        std::fs::write(&staged, b"new-binary").unwrap();
        std::fs::write(&current, b"old-binary").unwrap();
        let flags = ApplyFailureFlagsGuard::lock();
        flags.force_copy_failure();

        let err = apply_staged_update_at_paths(&staged, &current, None)
            .expect_err("forced copy failure should fail");
        assert!(err.message.contains("failed to copy staged binary"));
        assert_eq!(std::fs::read(&current).unwrap(), b"old-binary");
    }

    #[cfg(not(windows))]
    #[test]
    fn test_apply_staged_update_copy_and_restore_failure_surfaces_critical_error() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let current = dir.path().join("cara");
        std::fs::write(&staged, b"new-binary").unwrap();
        std::fs::write(&current, b"old-binary").unwrap();
        let flags = ApplyFailureFlagsGuard::lock();
        flags.force_copy_failure();
        flags.force_restore_failure();

        let err = apply_staged_update_at_paths(&staged, &current, None)
            .expect_err("forced copy+restore failure should fail");
        assert!(err.message.contains("CRITICAL: copy failed"));
        assert!(err.message.contains("restore failed"));
        assert!(err.message.contains("Backup path (if present):"));
    }

    #[test]
    fn test_parse_sigstore_bundle_missing_bundle_is_rejected() {
        let err = parse_sigstore_bundle(b"").expect_err("empty bundle must fail");
        assert!(err.message.contains("bundle parse failed"));
        assert!(!err.retryable);
        assert_eq!(err.phase, Some(UpdatePhase::Verified));
    }

    #[test]
    fn test_parse_sigstore_bundle_malformed_bundle_is_rejected() {
        let err = parse_sigstore_bundle(br#"{"kindVersion":"oops"}"#)
            .expect_err("malformed bundle must fail");
        assert!(err.message.contains("bundle parse failed"));
        assert!(!err.retryable);
        assert_eq!(err.phase, Some(UpdatePhase::Verified));
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_digest_missing_bundle_is_rejected() {
        let err = verify_bundle_signature_digest(
            parse_sigstore_digest(&sha256_bytes(b"artifact-bytes")).unwrap(),
            b"",
            &expected_identity_for_tag("v0.7.0"),
        )
        .await
        .expect_err("empty bundle must fail");
        assert!(err.message.contains("bundle parse failed"));
        assert!(!err.retryable);
        assert_eq!(err.phase, Some(UpdatePhase::Verified));
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_accepts_v070_sha256sums_bundle() {
        verify_bundle_signature_digest(
            parse_sigstore_digest(V070_SHA256SUMS_DIGEST).unwrap(),
            V070_SHA256SUMS_BUNDLE,
            &expected_identity_for_tag("v0.7.0"),
        )
        .await
        .expect("current release bundle should verify");
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_rejects_wrong_identity_for_valid_bundle() {
        let err = verify_bundle_signature_digest(
            parse_sigstore_digest(V070_SHA256SUMS_DIGEST).unwrap(),
            V070_SHA256SUMS_BUNDLE,
            "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v9.9.9",
        )
        .await
        .expect_err("wrong identity must fail verification");
        assert!(err.message.contains("bundle verification failed"));
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_rejects_wrong_digest_for_valid_bundle() {
        let err = verify_bundle_signature_digest(
            parse_sigstore_digest(
                "bcc4012c1a51190fc354e4e5d77ebe0779097e36d30e3ce523efb05581394163",
            )
            .unwrap(),
            V070_SHA256SUMS_BUNDLE,
            &expected_identity_for_tag("v0.7.0"),
        )
        .await
        .expect_err("wrong digest must fail verification");
        assert!(err.message.contains("bundle verification failed"));
        assert!(!err.retryable);
    }

    #[test]
    fn test_verify_sigstore_bundle_rejects_wrong_issuer_for_valid_bundle() {
        let bundle = parse_sigstore_bundle(V070_SHA256SUMS_BUNDLE).unwrap();
        let trust_root = load_embedded_sigstore_trust_root().unwrap();
        let policy = VerificationPolicy {
            identity: Some(expected_identity_for_tag("v0.7.0")),
            issuer: Some("https://accounts.google.com".to_string()),
            verify_tlog: true,
            verify_timestamp: true,
            verify_certificate: true,
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        };

        let err = verify_sigstore_bundle_with_policy_sync(
            parse_sigstore_digest(V070_SHA256SUMS_DIGEST).unwrap(),
            &bundle,
            &policy,
            &trust_root,
        )
        .expect_err("wrong issuer must fail verification");
        assert!(err.message.contains("bundle verification failed"));
        assert!(!err.retryable);
    }

    #[test]
    fn test_build_sigstore_policy_requires_expected_issuer_and_identity() {
        let policy = build_sigstore_policy("expected-identity");
        assert_eq!(policy.identity.as_deref(), Some("expected-identity"));
        assert_eq!(policy.issuer.as_deref(), Some(EXPECTED_OIDC_ISSUER));
        assert!(policy.verify_tlog);
        assert!(policy.verify_timestamp);
        assert!(policy.verify_certificate);
        assert_eq!(policy.clock_skew_seconds, DEFAULT_CLOCK_SKEW_SECONDS);
    }

    #[tokio::test]
    async fn test_load_sigstore_trust_root_offline_tuf_cache_matches_embedded_production() {
        let dir = tempfile::tempdir().unwrap();
        let targets_dir = dir.path().join("sigstore-rust");
        std::fs::create_dir_all(&targets_dir).unwrap();
        std::fs::write(
            targets_dir.join(TRUSTED_ROOT_TARGET),
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .unwrap();

        let root = load_sigstore_trust_root_with_config(
            TufConfig::production()
                .with_cache_dir(dir.path().to_path_buf())
                .offline(),
        )
        .await
        .expect("offline TUF loader should read cached trusted root");
        let embedded = load_embedded_sigstore_trust_root().unwrap();

        assert_eq!(
            serde_json::to_value(&root).unwrap(),
            serde_json::to_value(&embedded).unwrap()
        );
    }

    #[tokio::test]
    async fn test_load_sigstore_trust_root_offline_production_falls_back_to_embedded() {
        let dir = tempfile::tempdir().unwrap();
        let root = load_sigstore_trust_root_with_config(
            TufConfig::production()
                .with_cache_dir(dir.path().to_path_buf())
                .offline(),
        )
        .await
        .expect("offline production loader should fall back to embedded trusted root");
        let embedded = load_embedded_sigstore_trust_root().unwrap();

        assert_eq!(
            serde_json::to_value(&root).unwrap(),
            serde_json::to_value(&embedded).unwrap()
        );
    }

    #[tokio::test]
    async fn test_load_sigstore_trust_root_offline_custom_missing_cache_failure_is_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_sigstore_trust_root_with_config(
            TufConfig::custom("https://example.invalid/sigstore-tuf/", PRODUCTION_TUF_ROOT)
                .with_cache_dir(dir.path().to_path_buf())
                .offline(),
        )
        .await
        .expect_err("custom offline TUF loader should fail without cached target");

        assert!(err.retryable);
        assert_eq!(err.phase, Some(UpdatePhase::Verified));
        assert!(err
            .message
            .contains("failed to initialize sigstore trust root"));
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_accepts_v070_sha256sums_bundle_with_offline_tuf_root() {
        let dir = tempfile::tempdir().unwrap();
        let targets_dir = dir.path().join("sigstore-rust");
        std::fs::create_dir_all(&targets_dir).unwrap();
        std::fs::write(
            targets_dir.join(TRUSTED_ROOT_TARGET),
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .unwrap();

        let trust_root = load_sigstore_trust_root_with_config(
            TufConfig::production()
                .with_cache_dir(dir.path().to_path_buf())
                .offline(),
        )
        .await
        .expect("offline TUF loader should read cached trusted root");

        verify_parsed_bundle_signature_with_trust_root(
            parse_sigstore_digest(V070_SHA256SUMS_DIGEST).unwrap(),
            parse_sigstore_bundle(V070_SHA256SUMS_BUNDLE).unwrap(),
            &expected_identity_for_tag("v0.7.0"),
            trust_root,
        )
        .await
        .expect("offline TUF trust root should verify the current release bundle");
    }

    #[tokio::test]
    async fn test_auto_resume_with_backoff_no_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let result =
            auto_resume_with_backoff(dir.path().to_path_buf(), "0.1.0".to_string(), true, None)
                .await
                .expect("no transaction should not fail");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_auto_resume_with_backoff_applied_transaction_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        tx.state = UpdateTransactionState::Applied;
        tx.phase = UpdatePhase::Applied;
        tx.retryable = false;
        persist_update_transaction(dir.path(), &tx).unwrap();

        let result =
            auto_resume_with_backoff(dir.path().to_path_buf(), "0.1.0".to_string(), true, None)
                .await
                .expect("applied transaction should not fail");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_auto_resume_with_backoff_shutdown_signal_skips_resume() {
        let dir = tempfile::tempdir().unwrap();
        let mut tx = make_new_transaction("0.1.0", &expected_asset_name());
        tx.state = UpdateTransactionState::InProgress;
        tx.phase = UpdatePhase::Downloading;
        tx.retryable = true;
        tx.attempt = 1;
        tx.max_attempts = 3;
        persist_update_transaction(dir.path(), &tx).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).unwrap();
        let result = auto_resume_with_backoff(
            dir.path().to_path_buf(),
            "0.1.0".to_string(),
            true,
            Some(shutdown_rx),
        )
        .await
        .expect("shutdown short-circuit should not fail");
        assert!(result.is_none());
    }
}
