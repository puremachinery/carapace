//! Shared updater pipeline with mandatory Sigstore verification and transaction-based resume.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::policy::SingleX509ExtPolicy;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

pub const EXPECTED_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const EXPECTED_IDENTITY_PREFIX: &str =
    "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/";

pub const DEFAULT_RESUME_MAX_ATTEMPTS: u32 = 3;
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;

static UPDATE_OPERATION_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
static TEST_FORCE_COPY_FAIL: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    #[allow(dead_code)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTransaction {
    pub id: String,
    pub version: String,
    pub asset_name: String,
    pub state: UpdateTransactionState,
    pub attempt: u32,
    pub max_attempts: u32,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub staged_path: Option<String>,
    pub bundle_path: Option<String>,
    pub sha256: Option<String>,
    pub last_error: Option<String>,
    pub phase: UpdatePhase,
    pub retryable: bool,
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
}

#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub current_version: String,
    pub state_dir: PathBuf,
    pub requested_version: Option<String>,
    pub apply_update: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateError {
    pub phase: Option<UpdatePhase>,
    pub retryable: bool,
    pub message: String,
}

impl UpdateError {
    fn retryable<M: Into<String>>(phase: Option<UpdatePhase>, message: M) -> Self {
        Self {
            phase,
            retryable: true,
            message: message.into(),
        }
    }

    fn non_retryable<M: Into<String>>(phase: Option<UpdatePhase>, message: M) -> Self {
        Self {
            phase,
            retryable: false,
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    state_dir.join("updates").join("transaction.json")
}

fn update_staging_path(state_dir: &Path, version: &str) -> PathBuf {
    state_dir.join("updates").join(format!("cara-{version}"))
}

fn update_bundle_path(state_dir: &Path, version: &str) -> PathBuf {
    state_dir
        .join("updates")
        .join(format!("cara-{version}.bundle"))
}

pub fn load_update_transaction(state_dir: &Path) -> Result<Option<UpdateTransaction>, UpdateError> {
    let path = update_transaction_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }

    let data = fs::read(&path).map_err(|err| {
        UpdateError::retryable(
            None,
            format!(
                "failed to read update transaction '{}': {err}",
                path.display()
            ),
        )
    })?;

    serde_json::from_slice::<UpdateTransaction>(&data)
        .map(Some)
        .map_err(|err| {
            UpdateError::non_retryable(
                None,
                format!(
                    "failed to parse update transaction '{}': {err}",
                    path.display()
                ),
            )
        })
}

pub fn persist_update_transaction(
    state_dir: &Path,
    transaction: &UpdateTransaction,
) -> Result<(), UpdateError> {
    let path = update_transaction_path(state_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            UpdateError::retryable(
                Some(transaction.phase),
                format!("failed to create update dir '{}': {err}", parent.display()),
            )
        })?;
    }

    let tmp_path = {
        let mut os = path.as_os_str().to_os_string();
        os.push(".tmp");
        PathBuf::from(os)
    };

    let mut payload = serde_json::to_vec_pretty(transaction).map_err(|err| {
        UpdateError::non_retryable(
            Some(transaction.phase),
            format!("failed to serialize update transaction: {err}"),
        )
    })?;
    payload.push(b'\n');

    let result = (|| -> std::io::Result<()> {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&payload)?;
        file.sync_data()?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    })();

    if let Err(err) = result {
        let _ = fs::remove_file(&tmp_path);
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

pub fn clear_update_transaction(state_dir: &Path) -> Result<(), UpdateError> {
    let path = update_transaction_path(state_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(UpdateError::retryable(
            None,
            format!(
                "failed to remove update transaction '{}': {err}",
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

pub fn compute_sha256(path: &Path) -> Result<String, UpdateError> {
    let mut file = File::open(path).map_err(|e| {
        UpdateError::retryable(
            None,
            format!("failed to open file '{}' for hashing: {e}", path.display()),
        )
    })?;
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
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn verify_checksum(actual_hash: &str, checksum_text: &str) -> Result<(), UpdateError> {
    let expected = checksum_text
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

pub fn apply_staged_update(staged_path: &str) -> Result<ApplyResult, UpdateError> {
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
    apply_staged_update_at_paths(staged, &current_path)
}

fn apply_staged_update_at_paths(
    staged: &Path,
    current_path: &Path,
) -> Result<ApplyResult, UpdateError> {
    let staged_meta = fs::metadata(staged).map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("staged binary not found at '{}': {e}", staged.display()),
        )
    })?;
    if staged_meta.len() == 0 {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("staged binary at '{}' is empty", staged.display()),
        ));
    }

    let sha256 = compute_sha256(staged)?;
    let binary_path = current_path.to_string_lossy().into_owned();

    #[cfg(windows)]
    {
        return apply_staged_update_windows(staged, sha256, binary_path);
    }

    let backup_path = format!("{}.bak", current_path.display());

    fs::rename(current_path, &backup_path).map_err(|e| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("failed to rename current binary to .bak: {e}"),
        )
    })?;

    let copy_result: Result<(), std::io::Error> = {
        #[cfg(test)]
        {
            if TEST_FORCE_COPY_FAIL.swap(false, Ordering::SeqCst) {
                Err(std::io::Error::other("forced copy failure"))
            } else {
                fs::copy(staged, current_path).map(|_| ())
            }
        }
        #[cfg(not(test))]
        {
            fs::copy(staged, current_path).map(|_| ())
        }
    };

    if let Err(copy_err) = copy_result {
        if let Err(restore_err) = fs::rename(&backup_path, current_path) {
            return Err(UpdateError::non_retryable(
                Some(UpdatePhase::Applying),
                format!(
                    "CRITICAL: copy failed ({copy_err}) AND restore failed ({restore_err}). Backup at: {backup_path}"
                ),
            ));
        }
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            format!("failed to copy staged binary to current path: {copy_err}"),
        ));
    }

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

    if let Err(err) = fs::remove_file(&backup_path) {
        tracing::warn!(
            path = %backup_path,
            error = %err,
            "failed to remove backup file"
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

pub fn cleanup_old_binaries(state_dir: &Path) {
    cleanup_bak_files_near_exe();
    cleanup_stale_staged_updates(state_dir);
}

fn cleanup_bak_files_near_exe() {
    let exe = match std::env::current_exe() {
        Ok(v) => v,
        Err(_) => return,
    };
    let parent = match exe.parent() {
        Some(v) => v,
        None => return,
    };
    let entries = match fs::read_dir(parent) {
        Ok(v) => v,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext == "bak" || ext == "old")
        {
            if let Err(err) = fs::remove_file(&path) {
                tracing::warn!(path = %path.display(), error = %err, "failed to remove old binary");
            }
        }
    }
}

fn cleanup_stale_staged_updates(state_dir: &Path) {
    let updates_dir = state_dir.join("updates");
    let entries = match fs::read_dir(&updates_dir) {
        Ok(v) => v,
        Err(_) => return,
    };

    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = path
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
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

fn is_retryable_release_http_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
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
            UpdateError::retryable(None, format!("failed to fetch release info: {err}"))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let message = format!("GitHub API returned HTTP {status}: {body}");
        return if is_retryable_release_http_status(status) {
            Err(UpdateError::retryable(None, message))
        } else {
            Err(UpdateError::non_retryable(None, message))
        };
    }

    response.json::<GitHubRelease>().await.map_err(|err| {
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
                format!("failed to download artifact: {err}"),
            )
        })?;

    if !response.status().is_success() {
        return Err(UpdateError::retryable(
            Some(UpdatePhase::Downloading),
            format!("artifact download returned status {}", response.status()),
        ));
    }

    let body = response.bytes().await.map_err(|err| {
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

    Ok(body.to_vec())
}

async fn verify_bundle_signature(
    binary_bytes: &[u8],
    bundle_bytes: &[u8],
    expected_identity: &str,
) -> Result<(), UpdateError> {
    let bundle =
        serde_json::from_slice::<sigstore::bundle::Bundle>(bundle_bytes).map_err(|err| {
            UpdateError::non_retryable(
                Some(UpdatePhase::Verified),
                format!("bundle parse failed: {err}"),
            )
        })?;
    let expected_identity = expected_identity.to_string();
    let input = binary_bytes.to_vec();
    tokio::task::spawn_blocking(move || {
        let verifier =
            sigstore::bundle::verify::blocking::Verifier::production().map_err(|err| {
                UpdateError::retryable(
                    Some(UpdatePhase::Verified),
                    format!("failed to initialize sigstore trust root: {err}"),
                )
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&input);

        let issuer_policy = sigstore::bundle::verify::policy::OIDCIssuer::new(EXPECTED_OIDC_ISSUER);
        let identity_policy = sigstore::bundle::verify::policy::Identity::new(
            &expected_identity,
            EXPECTED_OIDC_ISSUER,
        );
        let all = sigstore::bundle::verify::policy::AllOf::new([
            &issuer_policy as &dyn sigstore::bundle::verify::policy::VerificationPolicy,
            &identity_policy as &dyn sigstore::bundle::verify::policy::VerificationPolicy,
        ])
        .ok_or_else(|| {
            UpdateError::non_retryable(
                Some(UpdatePhase::Verified),
                "invalid sigstore verification policy",
            )
        })?;

        verifier
            .verify_digest(hasher, bundle, &all, true)
            .map_err(|err| {
                let message = format!("bundle verification failed: {err}");
                UpdateError::non_retryable(Some(UpdatePhase::Verified), message)
            })
    })
    .await
    .map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Verified),
            format!("bundle verification worker task failed: {err}"),
        )
    })?
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

    let mut staged_file = tokio::fs::File::create(&staged_path).await.map_err(|err| {
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

    tokio::fs::write(&bundle_path, &bundle_bytes)
        .await
        .map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "failed to write bundle file '{}': {err}",
                    bundle_path.display()
                ),
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o755)).map_err(|err| {
            UpdateError::retryable(
                Some(UpdatePhase::Downloading),
                format!(
                    "failed to set executable permissions on staged file '{}': {err}",
                    staged_path.display()
                ),
            )
        })?;
    }

    let staged_hash = sha256_bytes(&binary_bytes);
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
    verify_bundle_signature(&binary_bytes, &bundle_bytes, &expected_identity).await?;

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

        let entry = checksum_text.lines().find(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|name| name == asset_name)
        });
        if let Some(line) = entry {
            verify_checksum(&staged_hash, line)?;
            checksum_verified = true;
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
        });
    }

    transition(
        tx,
        UpdatePhase::Applying,
        UpdateTransactionState::InProgress,
        None,
        true,
    );
    persist_update_transaction(&request.state_dir, tx)?;

    let staged_path = tx.staged_path.as_deref().unwrap_or_default();
    let expected_hash = tx.sha256.clone().ok_or_else(|| {
        UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            "missing staged artifact hash before apply",
        )
    })?;
    let on_disk_hash = compute_sha256(Path::new(staged_path)).map_err(|err| {
        UpdateError::retryable(
            Some(UpdatePhase::Applying),
            format!(
                "failed to verify staged artifact before apply: {}",
                err.message
            ),
        )
    })?;
    if on_disk_hash != expected_hash {
        return Err(UpdateError::non_retryable(
            Some(UpdatePhase::Applying),
            "staged artifact changed after verification",
        ));
    }

    let apply_result = apply_staged_update(staged_path)?;

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
    persist_update_transaction(&request.state_dir, &tx)?;
    Ok((tx, release))
}

async fn install_with_transaction(request: &InstallRequest) -> Result<InstallOutcome, UpdateError> {
    let existing = load_update_transaction(&request.state_dir)?;
    if let Some(tx) = existing.as_ref() {
        tracing::info!(transaction_id = %tx.id, phase = ?tx.phase, state = ?tx.state, "resuming existing update transaction");
    }

    let (mut tx, release_for_first_run) = match existing {
        Some(mut tx) => {
            if tx.state == UpdateTransactionState::Applied {
                clear_update_transaction(&request.state_dir)?;
                let (tx, release) = prepare_transaction(request).await?;
                (tx, Some(release))
            } else if tx.state == UpdateTransactionState::Failed && !tx.retryable {
                let message = tx
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "non-retryable update failure".to_string());
                return Err(UpdateError::non_retryable(
                    Some(UpdatePhase::Failed),
                    message,
                ));
            } else {
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

    let outcome = run_transaction_once(request, &mut tx, release_for_first_run).await;
    match outcome {
        Ok(value) => Ok(value),
        Err(err) => {
            record_failure(&request.state_dir, &mut tx, &err)?;
            Err(err)
        }
    }
}

pub async fn install_or_resume(request: InstallRequest) -> Result<InstallOutcome, UpdateError> {
    let _guard = UPDATE_OPERATION_LOCK.lock().await;
    install_with_transaction(&request).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(is_retryable_release_http_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(is_retryable_release_http_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(!is_retryable_release_http_status(
            reqwest::StatusCode::NOT_FOUND
        ));
    }

    #[test]
    fn test_verify_checksum_accepts_gnu_format() {
        let hash = sha256_bytes(b"hello");
        let line = format!("{hash}  cara-x86_64-linux");
        verify_checksum(&hash, &line).expect("checksum should pass");
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
    fn test_transaction_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut tx = make_new_transaction("0.1.0", "cara-x86_64-linux");
        tx.attempt = 2;
        tx.staged_path = Some("/tmp/staged".to_string());
        tx.bundle_path = Some("/tmp/staged.bundle".to_string());
        persist_update_transaction(dir.path(), &tx).unwrap();

        let loaded = load_update_transaction(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.version, "0.1.0");
        assert_eq!(loaded.attempt, 2);
        assert_eq!(loaded.staged_path.as_deref(), Some("/tmp/staged"));
        assert_eq!(loaded.bundle_path.as_deref(), Some("/tmp/staged.bundle"));
    }

    #[test]
    fn test_transaction_resume_pending_logic() {
        let mut tx = make_new_transaction("0.1.0", "cara-x86_64-linux");
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
        let tx = make_new_transaction("0.1.0", "cara-x86_64-linux");
        persist_update_transaction(dir.path(), &tx).unwrap();
        clear_update_transaction(dir.path()).unwrap();
        assert!(load_update_transaction(dir.path()).unwrap().is_none());
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

    #[test]
    fn test_apply_staged_update_success_for_paths() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let current = dir.path().join("cara");
        std::fs::write(&staged, b"new-binary").unwrap();
        std::fs::write(&current, b"old-binary").unwrap();

        let result = apply_staged_update_at_paths(&staged, &current).expect("apply should succeed");
        assert!(result.applied);
        assert_eq!(result.binary_path, current.to_string_lossy());
        assert_eq!(std::fs::read(&current).unwrap(), b"new-binary");
        assert!(!current.with_extension("bak").exists());
    }

    #[test]
    fn test_apply_staged_update_copy_failure_restores_original() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let current = dir.path().join("cara");
        std::fs::write(&staged, b"new-binary").unwrap();
        std::fs::write(&current, b"old-binary").unwrap();
        TEST_FORCE_COPY_FAIL.store(true, Ordering::SeqCst);

        let err = apply_staged_update_at_paths(&staged, &current)
            .expect_err("forced copy failure should fail");
        assert!(err.message.contains("failed to copy staged binary"));
        assert_eq!(std::fs::read(&current).unwrap(), b"old-binary");
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_missing_bundle_is_rejected() {
        let err = verify_bundle_signature(
            b"artifact-bytes",
            b"",
            "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v0.1.0",
        )
        .await
        .expect_err("empty bundle must fail");
        assert!(err.message.contains("bundle parse failed"));
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn test_verify_bundle_signature_malformed_bundle_is_rejected() {
        let err = verify_bundle_signature(
            b"artifact-bytes",
            br#"{"kindVersion":"oops"}"#,
            "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v0.1.0",
        )
        .await
        .expect_err("malformed bundle must fail");
        assert!(err.message.contains("bundle parse failed"));
        assert!(!err.retryable);
    }
}
