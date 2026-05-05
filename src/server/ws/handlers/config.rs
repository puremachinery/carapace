//! Config handlers.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use super::super::*;

static CONFIG_WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static CONFIG_FILE_WRITE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Did the closure mutate the config? `Changed` triggers persistence;
/// `NoOp` skips the write so a wizard or merge-style caller reporting
/// "nothing to apply" doesn't recreate or overwrite the on-disk file.
/// The previous `bool` shape allowed `.map(|()| false)` to silently
/// drop persistence on every call — the named variants force callers
/// to think about the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigUpdateOutcome {
    Changed,
    NoOp,
}

impl ConfigUpdateOutcome {
    pub(crate) fn is_changed(self) -> bool {
        matches!(self, Self::Changed)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfigIssue {
    pub(crate) path: String,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) struct ConfigSnapshot {
    pub(crate) path: String,
    pub(crate) exists: bool,
    pub(crate) parsed: Value,
    pub(crate) raw_config: Value,
    pub(crate) valid: bool,
    pub(crate) config: Value,
    pub(crate) hash: Option<String>,
    pub(crate) issues: Vec<ConfigIssue>,
}

pub(crate) fn map_validation_issues(issues: Vec<config::ValidationIssue>) -> Vec<ConfigIssue> {
    issues
        .into_iter()
        .map(|issue| ConfigIssue {
            path: issue.path,
            message: issue.message,
        })
        .collect()
}

pub(crate) fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

pub(crate) fn read_config_snapshot() -> ConfigSnapshot {
    let path = config::get_config_path();
    let path_str = path.display().to_string();
    if !path.exists() {
        return ConfigSnapshot {
            path: path_str,
            exists: false,
            parsed: Value::Object(serde_json::Map::new()),
            raw_config: Value::Object(serde_json::Map::new()),
            valid: true,
            config: Value::Object(serde_json::Map::new()),
            hash: None,
            issues: Vec::new(),
        };
    }

    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) => {
            return ConfigSnapshot {
                path: path_str,
                exists: true,
                parsed: Value::Object(serde_json::Map::new()),
                raw_config: Value::Object(serde_json::Map::new()),
                valid: false,
                config: Value::Object(serde_json::Map::new()),
                hash: None,
                issues: vec![ConfigIssue {
                    path: "".to_string(),
                    message: format!("read failed: {}", err),
                }],
            }
        }
    };

    let hash = Some(sha256_hex(&raw));
    let parsed = json5::from_str::<Value>(&raw).unwrap_or(Value::Null);
    let (raw_config, config_value, mut issues, valid) =
        match config::load_config_pair_uncached(&path) {
            Ok((raw_cfg, cfg)) => {
                let issues = map_validation_issues(config::validate_config(&cfg));
                let valid = issues.is_empty();
                (raw_cfg, cfg, issues, valid)
            }
            Err(err) => {
                let issues = vec![ConfigIssue {
                    path: "".to_string(),
                    message: err.to_string(),
                }];
                (parsed.clone(), parsed.clone(), issues, false)
            }
        };

    if !valid && issues.is_empty() {
        issues.push(ConfigIssue {
            path: "".to_string(),
            message: "invalid config".to_string(),
        });
    }

    ConfigSnapshot {
        path: path_str,
        exists: true,
        parsed,
        raw_config,
        valid,
        config: config_value,
        hash,
        issues,
    }
}

fn require_config_base_hash(
    params: Option<&Value>,
    snapshot: &ConfigSnapshot,
) -> Result<(), ErrorShape> {
    if !snapshot.exists {
        return Ok(());
    }
    let base_hash = params
        .and_then(|v| v.get("baseHash"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let expected = snapshot.hash.as_deref();
    if expected.is_none() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config base hash unavailable; re-run config.get and retry",
            None,
        ));
    }
    let Some(base_hash) = base_hash else {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config base hash required; re-run config.get and retry",
            None,
        ));
    };
    if Some(base_hash) != expected {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config changed since last load; re-run config.get and retry",
            None,
        ));
    }
    Ok(())
}

/// Write a config value to disk atomically. Returns `Err(message)` on failure.
/// This is the `pub(crate)` helper so non-WS code (e.g. the control HTTP
/// endpoint) can persist config without depending on `ErrorShape`.
pub(crate) fn persist_config_file(path: &PathBuf, config_value: &Value) -> Result<(), String> {
    let _guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| "config write lock poisoned".to_string())?;
    let (existing_text, existing_raw) = read_existing_config_for_write(path)?;
    // Reject corrupt-base writes here too: a `(Some(raw), None)`
    // means the file exists on disk but failed to parse, so
    // `validate_locked_secret_preservation(None, ...)` would
    // short-circuit to Ok and the encrypted-secret preservation
    // check would be silently bypassed. Force the operator either
    // to fix the file or to use a corrupt-tolerant replacement
    // path (which doesn't exist on this code path — full
    // replacement still goes through `update_config_file_inner`'s
    // sibling guard, and that one rejects too).
    if existing_text.is_some() && existing_raw.is_none() {
        return Err(
            "config file failed to parse; refuse to write into an unparseable base — \
             fix the file on disk first or remove it"
                .to_string(),
        );
    }
    persist_config_file_locked(path, config_value, existing_raw.as_ref())
}

/// Persistence outcomes for `persist_config_file_with_base_hash`.
///
/// The conflict variant is the optimistic-concurrency loser case
/// (the on-disk hash drifted between snapshot and lock). Callers
/// surface it as 409 Conflict / `INVALID_REQUEST` so clients can
/// re-read and retry; previously this was distinguished by string
/// match on the `Err(String)` payload, which was brittle (a typo in
/// the message at the producer silently demoted both consumers from
/// 409 to 500).
#[derive(Debug)]
pub(crate) enum PersistConfigError {
    /// On-disk hash drifted between the caller's snapshot and the
    /// write-lock acquisition — caller must re-read and retry.
    ConflictingBaseHash(String),
    /// Anything else (I/O failure, validation, lock poison, etc.).
    Other(String),
}

impl PersistConfigError {
    pub(crate) fn into_message(self) -> String {
        match self {
            Self::ConflictingBaseHash(s) | Self::Other(s) => s,
        }
    }

    /// HTTP status mapping for the REST control surface. The
    /// optimistic-concurrency conflict is a client-side race, not a
    /// server fault — `409 Conflict` so callers can re-read and
    /// retry. Everything else is `500`.
    pub(crate) fn http_status(&self) -> axum::http::StatusCode {
        match self {
            Self::ConflictingBaseHash(_) => axum::http::StatusCode::CONFLICT,
            Self::Other(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub(crate) fn persist_config_file_with_base_hash(
    path: &PathBuf,
    config_value: &Value,
    expected_hash: Option<&str>,
) -> Result<(), PersistConfigError> {
    let _guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| PersistConfigError::Other("config write lock poisoned".to_string()))?;
    let (existing_text, existing_raw) =
        read_existing_config_for_write(path).map_err(PersistConfigError::Other)?;
    if path.exists() {
        let actual_hash = existing_text.as_deref().map(sha256_hex);
        if actual_hash.as_deref() != expected_hash {
            return Err(PersistConfigError::ConflictingBaseHash(
                "config changed since last load; re-read config and retry".to_string(),
            ));
        }
    }
    // Reject corrupt-base: `existing_text=Some, existing_raw=None`
    // means the on-disk file exists but failed to parse. Without this
    // guard, `persist_config_file_locked`'s
    // `validate_locked_secret_preservation(None, ...)` early-returns Ok
    // and the encrypted-secret preservation check is silently bypassed
    // — operator with a corrupt config + secret encryption disabled
    // could overwrite encrypted accessToken/storePassphrase in-place.
    if existing_text.is_some() && existing_raw.is_none() {
        return Err(PersistConfigError::Other(
            "config file failed to parse; refuse to write into an unparseable base — \
             fix the file on disk first or remove it"
                .to_string(),
        ));
    }
    persist_config_file_locked(path, config_value, existing_raw.as_ref())
        .map_err(PersistConfigError::Other)
}

pub(crate) fn update_config_file<F>(path: &PathBuf, update: F) -> Result<(), String>
where
    F: FnOnce(&mut Value) -> Result<(), String>,
{
    update_config_file_inner(path, |value| {
        update(value).map(|()| ConfigUpdateOutcome::Changed)
    })
}

/// Closure returns `ConfigUpdateOutcome` to express "changed vs no-op".
/// `NoOp` skips the persist step entirely so callers can express a
/// no-op without rewriting (or creating) the on-disk file.
pub(crate) fn try_update_config_file<F>(
    path: &PathBuf,
    update: F,
) -> Result<ConfigUpdateOutcome, String>
where
    F: FnOnce(&mut Value) -> Result<ConfigUpdateOutcome, String>,
{
    let mut applied = ConfigUpdateOutcome::NoOp;
    update_config_file_inner(path, |value| {
        let result = update(value);
        if let Ok(ConfigUpdateOutcome::Changed) = result {
            applied = ConfigUpdateOutcome::Changed;
        }
        result
    })?;
    Ok(applied)
}

fn update_config_file_inner<F>(path: &PathBuf, update: F) -> Result<(), String>
where
    F: FnOnce(&mut Value) -> Result<ConfigUpdateOutcome, String>,
{
    let _guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| "config write lock poisoned".to_string())?;
    let (existing_text, existing_raw) = read_existing_config_for_write(path)?;
    // Merge-style callers cannot operate on a corrupted base: a parse
    // failure means `existing_raw` is `None` while the file is
    // non-empty on disk. Treating that as "no existing config" and
    // building a fresh `{}` would silently clobber the
    // broken-but-recoverable original. Reject loudly so the operator
    // either fixes the file or uses `config.set` for a full
    // replacement.
    if existing_text.is_some() && existing_raw.is_none() {
        return Err(
            "config file failed to parse; refuse to merge into an unparseable base — \
             fix the file on disk first, or use `config.set` for a full replacement"
                .to_string(),
        );
    }
    let mut next_config = existing_raw
        .clone()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let outcome = update(&mut next_config)?;
    if !outcome.is_changed() {
        // Closure reported a no-op; preserve the on-disk file
        // verbatim. This avoids rewriting (or creating) the config
        // file with an unchanged value, matching the operator
        // expectation that a no-op wizard returning `applied=false`
        // touches no state.
        return Ok(());
    }
    persist_config_file_locked(path, &next_config, existing_raw.as_ref())
}

pub(super) fn update_config_file_with_error_shape<F>(
    path: &PathBuf,
    update: F,
) -> Result<(), ErrorShape>
where
    F: FnOnce(&mut Value) -> Result<(), ErrorShape>,
{
    try_update_config_file_with_error_shape(path, |value| {
        update(value).map(|()| ConfigUpdateOutcome::Changed)
    })
    .map(|_| ())
}

/// `ErrorShape`-flavoured no-op-aware variant of
/// `try_update_config_file`. Used by `persist_wizard_config` so an
/// `applied=false` outcome doesn't rewrite the config file.
pub(super) fn try_update_config_file_with_error_shape<F>(
    path: &PathBuf,
    update: F,
) -> Result<ConfigUpdateOutcome, ErrorShape>
where
    F: FnOnce(&mut Value) -> Result<ConfigUpdateOutcome, ErrorShape>,
{
    let mut handler_error = None;
    let result = try_update_config_file(path, |value| match update(value) {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            handler_error = Some(err);
            Err("handler rejected config update".to_string())
        }
    });
    match result {
        Ok(outcome) => Ok(outcome),
        Err(_) if handler_error.is_some() => Err(handler_error.expect("checked above")),
        Err(msg) => Err(error_shape(ERROR_UNAVAILABLE, &msg, None)),
    }
}

fn read_existing_config_for_write(path: &Path) -> Result<(Option<String>, Option<Value>), String> {
    if !path.exists() {
        return Ok((None, None));
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read existing config before write: {}", err))?;
    // Tolerate a corrupted on-disk JSON5 here so a full-replacement
    // `config.set` can rewrite a broken config from scratch. The raw
    // text still flows out for hash-comparison purposes; merge-style
    // callers refuse to operate when the parsed value is `None` (see
    // the explicit `raw_config.is_null()` guard in the patch handler).
    let parsed = json5::from_str::<Value>(&raw).ok();
    Ok((Some(raw), parsed))
}

fn persist_config_file_locked(
    path: &PathBuf,
    config_value: &Value,
    existing_raw: Option<&Value>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create config dir: {}", err))?;
    }

    let mut config_value = config_value.clone();
    config::validate_locked_secret_preservation(existing_raw, &config_value)?;
    config::seal_config_secrets(&mut config_value)?;
    let content = serde_json::to_string_pretty(&config_value)
        .map_err(|err| format!("failed to serialize config: {}", err))?;
    let tmp_path = config_write_temp_path(path);
    {
        let mut file = fs::File::create(&tmp_path)
            .map_err(|err| format!("failed to write config: {}", err))?;
        file.write_all(content.as_bytes())
            .map_err(|err| format!("failed to write config: {}", err))?;
        file.write_all(b"\n")
            .map_err(|err| format!("failed to write config: {}", err))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync config: {}", err))?;
    }
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to replace config: {}", err));
    }
    // The dirent change from the rename is not durable until the parent
    // directory is fsynced; without this, a power loss after `config.set`
    // returns success can revert the config to its pre-rename contents.
    // Propagate the fsync error rather than swallowing it — a failed
    // dirent flush invalidates the success contract this function
    // advertises.
    sync_parent_dir_for_config(path)?;

    config::clear_cache();
    Ok(())
}

fn sync_parent_dir_for_config(path: &Path) -> Result<(), String> {
    crate::paths::sync_parent_dir_blocking(path)
        .map_err(|err| format!("failed to fsync config dir: {}", err))
}

fn config_write_temp_path(path: &Path) -> PathBuf {
    let counter = CONFIG_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("carapace.json"));
    file_name.push(format!(".tmp.{}.{counter}", std::process::id()));
    path.with_file_name(file_name)
}

#[cfg(test)]
pub(super) fn write_config_file(path: &PathBuf, config_value: &Value) -> Result<(), ErrorShape> {
    persist_config_file(path, config_value)
        .map_err(|msg| error_shape(ERROR_UNAVAILABLE, &msg, None))
}

/// Atomic config write with optimistic-concurrency check inside the file
/// lock. The pre-lock `require_config_base_hash` check at handler entry
/// guards against the operator's stale snapshot, but a write that races
/// another writer between the check and the lock acquisition would
/// otherwise still proceed. Re-checking against the on-disk hash inside
/// the lock closes that window.
pub(super) fn write_config_file_with_base_hash(
    path: &PathBuf,
    config_value: &Value,
    expected_hash: Option<&str>,
) -> Result<(), ErrorShape> {
    persist_config_file_with_base_hash(path, config_value, expected_hash).map_err(|err| match err {
        // Optimistic-concurrency conflict (the loser of a write/write
        // race) — surface it with the same code the pre-lock baseHash
        // check uses so callers can re-read and retry deterministically.
        PersistConfigError::ConflictingBaseHash(msg) => {
            error_shape(ERROR_INVALID_REQUEST, &msg, None)
        }
        PersistConfigError::Other(msg) => error_shape(ERROR_UNAVAILABLE, &msg, None),
    })
}

fn merge_patch(base: Value, patch: Value) -> Value {
    match (base, patch) {
        (_, Value::Null) => Value::Null,
        (Value::Object(mut base_map), Value::Object(patch_map)) => {
            for (key, patch_value) in patch_map {
                if patch_value.is_null() {
                    base_map.remove(&key);
                } else {
                    let base_value = base_map.remove(&key).unwrap_or(Value::Null);
                    let merged = merge_patch(base_value, patch_value);
                    base_map.insert(key, merged);
                }
            }
            Value::Object(base_map)
        }
        (_, patch_value) => patch_value,
    }
}

fn reject_protected_config_changes(before: &Value, after: &Value) -> Result<(), ErrorShape> {
    let changed = config::changed_protected_config_prefixes(before, after);
    if changed.is_empty() {
        return Ok(());
    }
    Err(error_shape(
        ERROR_INVALID_REQUEST,
        &format!(
            "Cannot modify protected configuration through WebSocket config methods: {}",
            changed.join(", ")
        ),
        Some(json!({ "protected": changed })),
    ))
}

pub(super) fn handle_config_get(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    let key = params
        .and_then(|v| v.get("key"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    if let Some(key) = key {
        // Serve from raw_config (which preserves `enc:v2:` ciphertexts)
        // and apply key-name redaction as defense-in-depth so plaintext
        // secrets never leave the gateway, even when
        // CARAPACE_CONFIG_PASSWORD is unset and the on-disk file holds
        // raw values. `redact_value_at_key` handles leaf strings
        // directly using the trailing path segment as the secret-name
        // hint — no wrap-in-temp-object dance needed.
        let mut value = get_value_at_path(&snapshot.raw_config, key).unwrap_or(Value::Null);
        let leaf_name = key.rsplit('.').next().unwrap_or(key);
        crate::logging::redact::redact_value_at_key(&mut value, leaf_name);
        return Ok(json!({
            "key": key,
            "value": value
        }));
    }

    let mut redacted_config = snapshot.raw_config.clone();
    crate::logging::redact::redact_json_value(&mut redacted_config);
    let mut redacted_parsed = snapshot.parsed.clone();
    crate::logging::redact::redact_json_value(&mut redacted_parsed);

    // `raw` (literal file text) is intentionally omitted. It can contain
    // plaintext secrets when CARAPACE_CONFIG_PASSWORD is unset, and regex
    // scrubbing of JSON5 text is unreliable. Clients should use the
    // structured `parsed` / `config` views.
    Ok(json!({
        "path": snapshot.path,
        "exists": snapshot.exists,
        "raw": Value::Null,
        "parsed": redacted_parsed,
        "valid": snapshot.valid,
        "config": redacted_config,
        "hash": snapshot.hash,
        "issues": snapshot.issues,
        "warnings": []
    }))
}

pub(super) fn handle_config_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    require_config_base_hash(params, &snapshot)?;

    let raw = params
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw is required", None))?;
    let parsed = json5::from_str::<Value>(raw)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if !parsed.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.set raw must be an object",
            None,
        ));
    }
    // Compare against `raw_config` (the on-disk values, with env-var
    // placeholders preserved) rather than `parsed` (resolved). With
    // `parsed`, a caller submitting `${MATRIX_PASSWORD}` for a
    // currently-env-resolved protected path would trip the
    // protected-change check even though they're not rotating the
    // secret — and any merge would silently expand placeholders into
    // plaintext on disk.
    reject_protected_config_changes(&snapshot.raw_config, &parsed)?;
    let issues = map_validation_issues(config::validate_config(&parsed));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file_with_base_hash(
        &config::get_config_path(),
        &parsed,
        snapshot.hash.as_deref(),
    )?;
    // Echoing back `parsed` directly would expose any plaintext secret the
    // caller did NOT supply (e.g., they patched a benign field; the
    // response would still carry the existing matrix.accessToken etc.
    // when the on-disk file holds raw values). Always run the same
    // redactor used by config.get before returning.
    let mut redacted_response = parsed.clone();
    crate::logging::redact::redact_json_value(&mut redacted_response);
    Ok(json!({
        "ok": true,
        "path": config::get_config_path().display().to_string(),
        "config": redacted_response
    }))
}

pub(super) fn handle_config_apply(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    require_config_base_hash(params, &snapshot)?;

    let raw = params
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw is required", None))?;
    let parsed = json5::from_str::<Value>(raw)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if !parsed.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.apply raw must be an object",
            None,
        ));
    }
    // Compare against `raw_config` for the same reason as
    // `handle_config_set` — preserve env-var placeholders.
    reject_protected_config_changes(&snapshot.raw_config, &parsed)?;
    let issues = map_validation_issues(config::validate_config(&parsed));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file_with_base_hash(
        &config::get_config_path(),
        &parsed,
        snapshot.hash.as_deref(),
    )?;
    let mut redacted_response = parsed.clone();
    crate::logging::redact::redact_json_value(&mut redacted_response);
    Ok(json!({
        "ok": true,
        "path": config::get_config_path().display().to_string(),
        "config": redacted_response
    }))
}

pub(super) fn handle_config_patch(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    require_config_base_hash(params, &snapshot)?;

    // Refuse to patch a corrupted base. Without this guard, `merge_patch`
    // applied to a `Value::Null` raw view returns just the patch
    // contents, silently rewriting an unparseable config file with only
    // the patch — destroying the operator's broken-but-recoverable
    // original. Force the operator to use `config.set` (full replacement)
    // when the on-disk file failed to parse.
    if snapshot.exists && snapshot.raw_config.is_null() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config file failed to parse; refuse to patch unparseable base — \
             use config.set with a full replacement, or fix the file on disk first",
            None,
        ));
    }

    let raw = params
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw is required", None))?;
    let patch_value = json5::from_str::<Value>(raw)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if !patch_value.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.patch raw must be an object",
            None,
        ));
    }

    // Merge against `raw_config` (env-var placeholders preserved)
    // rather than `parsed` (resolved). With `parsed`, `merge_patch`
    // would expand every `${MATRIX_PASSWORD}`-style placeholder into
    // its plaintext value before writing the merged result back to
    // disk — silently materializing operator secrets into the config
    // file even when the patch only touched a benign field.
    let merged = merge_patch(snapshot.raw_config.clone(), patch_value);
    reject_protected_config_changes(&snapshot.raw_config, &merged)?;
    let issues = map_validation_issues(config::validate_config(&merged));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }

    write_config_file_with_base_hash(
        &config::get_config_path(),
        &merged,
        snapshot.hash.as_deref(),
    )?;
    // The merged result inherits every existing field from snapshot.parsed
    // — including any plaintext secrets the on-disk file already holds.
    // A caller patching a benign field could otherwise read secrets they
    // never sent. Apply the same redactor used by config.get.
    let mut redacted_response = merged.clone();
    crate::logging::redact::redact_json_value(&mut redacted_response);
    Ok(json!({
        "ok": true,
        "path": config::get_config_path().display().to_string(),
        "config": redacted_response
    }))
}

pub(super) fn handle_config_validate(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let raw = params.and_then(|v| v.get("raw")).and_then(|v| v.as_str());

    let parsed = if let Some(raw) = raw {
        json5::from_str::<Value>(raw)
            .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?
    } else {
        params
            .and_then(|v| v.get("config"))
            .cloned()
            .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw or config is required", None))?
    };

    if !parsed.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.validate value must be an object",
            None,
        ));
    }

    let issues = map_validation_issues(config::validate_config(&parsed));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }

    Ok(json!({
        "ok": true,
        "valid": true,
        "issues": []
    }))
}

pub(super) fn handle_config_schema() -> Result<Value, ErrorShape> {
    let keys = config::schema::known_top_level_keys();
    let mut properties = serde_json::Map::new();
    for key in keys {
        properties.insert(key.to_string(), json!({ "type": "object" }));
    }

    Ok(json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "knownKeys": keys
    }))
}

/// Handle the `config.reload` WS method (admin-only).
///
/// Routes through the hot-reload bridge so the WS reload exercises the
/// same provider-validation pipeline as the file-watcher and SIGHUP paths.
/// A reload that drops the LLM provider is rejected before the cache is
/// touched; the client gets an error response.
pub(super) async fn handle_config_reload(state: &WsServerState) -> Result<Value, ErrorShape> {
    use crate::config::watcher::{manual_reload_mode, mode_label};
    use crate::server::startup::{ReloadCommand, ReloadCommandResult};

    let mode = manual_reload_mode();

    let Some(command_tx) = state.reload_command_tx() else {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            "config-reload bridge is not running; reload requests cannot be processed",
            None,
        ));
    };
    let (respond_to, response_rx) = tokio::sync::oneshot::channel();
    if command_tx
        .send(ReloadCommand {
            mode: mode.clone(),
            respond_to,
        })
        .await
        .is_err()
    {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            "config-reload bridge has shut down; reload not delivered",
            None,
        ));
    }
    // The bridge always replies; an `Err(_)` here would mean the bridge task
    // panicked between command receipt and respond_to.send — fold it into a
    // generic LoadError so the WS handler never silently no-ops.
    let result = response_rx.await.unwrap_or_else(|_| {
        ReloadCommandResult::LoadError(
            "config-reload bridge dropped the response without replying".into(),
        )
    });
    match result {
        ReloadCommandResult::Applied { warnings } => Ok(json!({
            "ok": true,
            "mode": mode_label(&mode),
            "warnings": warnings,
        })),
        ReloadCommandResult::Reverted => Err(error_shape(
            ERROR_UNAVAILABLE,
            "reload rejected: the new config has no LLM provider configured (or build_providers \
             failed). The previous config is still active.",
            None,
        )),
        ReloadCommandResult::LoadError(message) => {
            // Log the full diagnostic server-side and surface a generic
            // summary to the WS client. The full message can include
            // absolute file paths, OS errnos, and JSON5 parser positions —
            // useful for the operator reading server logs but a leak vector
            // when WS error responses get forwarded to logging aggregators
            // or dashboards.
            tracing::error!("config.reload failed: {}", message);
            Err(error_shape(
                ERROR_UNAVAILABLE,
                "config reload failed; see server logs for details",
                None,
            ))
        }
    }
}

/// Broadcast a `config.changed` event to all connected WS clients.
///
/// This is called after a successful config reload (from file watcher, SIGHUP,
/// or the `config.reload` WS method).
pub fn broadcast_config_changed(state: &WsServerState, mode: &str) {
    let payload = json!({
        "mode": mode,
        "ts": now_ms()
    });
    broadcast_event(state, "config.changed", payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_write_temp_path_is_unique_in_target_dir() {
        let path = PathBuf::from("config-dir").join("carapace.json");
        let first = config_write_temp_path(&path);
        let second = config_write_temp_path(&path);

        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert!(first
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("carapace.json.tmp.")));
    }

    #[test]
    fn test_persist_config_file_rejects_locked_secret_overwrite_without_password() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = crate::test_support::env::ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        fs::write(
            &path,
            r#"{
                matrix: {
                    accessToken: "enc:v2:nonce:ciphertext:salt",
                    deviceId: "DEVICE"
                }
            }"#,
        )
        .expect("write existing config");

        let candidate = json!({
            "matrix": {
                "accessToken": null,
                "deviceId": "DEVICE"
            }
        });
        let err = persist_config_file(&path, &candidate)
            .expect_err("locked encrypted secret must not be overwritten");

        assert!(err.contains("CARAPACE_CONFIG_PASSWORD is required"));
        let current = fs::read_to_string(&path).expect("read config");
        assert!(current.contains("enc:v2:nonce:ciphertext:salt"));
    }

    #[test]
    fn test_persist_config_file_with_base_hash_rejects_stale_write() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        let original = r#"{ gateway: { controlUi: { enabled: false } } }"#;
        fs::write(&path, original).expect("write original config");
        let stale_hash = sha256_hex(original);
        fs::write(&path, r#"{ gateway: { controlUi: { enabled: true } } }"#)
            .expect("write concurrent config");

        let err = persist_config_file_with_base_hash(
            &path,
            &json!({"gateway": {"controlUi": {"enabled": false}}}),
            Some(&stale_hash),
        )
        .expect_err("stale base hash must be rejected");

        assert!(matches!(err, PersistConfigError::ConflictingBaseHash(_)));
    }

    #[test]
    fn test_handle_config_validate_accepts_object() {
        let params = json!({ "config": {} });
        let result = handle_config_validate(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["valid"], true);
    }

    /// `config.get` must never return plaintext secrets — neither in the
    /// full snapshot nor in per-key lookups. The previous WS handler shape
    /// returned `snapshot.config` (the *decrypted* config view), which
    /// leaked any sealed secret to operators with control-API access.
    #[test]
    fn test_handle_config_get_redacts_secret_paths() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = crate::test_support::env::ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        fs::write(
            &path,
            r#"{
                matrix: {
                    accessToken: "plaintext-token-value-must-not-leak",
                    password: "plaintext-password-value-must-not-leak",
                    storePassphrase: "plaintext-passphrase-must-not-leak",
                    deviceId: "DEVICE",
                    homeserverUrl: "https://matrix.example.com"
                }
            }"#,
        )
        .expect("write config");
        env.set("CARAPACE_CONFIG_PATH", path.display().to_string());
        crate::config::clear_cache();

        let response = handle_config_get(None).expect("config.get full snapshot");
        let matrix = response
            .get("config")
            .and_then(|c| c.get("matrix"))
            .expect("matrix subtree");
        assert_eq!(
            matrix.get("accessToken").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "accessToken must be redacted in full snapshot"
        );
        assert_eq!(
            matrix.get("password").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "password must be redacted in full snapshot"
        );
        assert_eq!(
            matrix.get("storePassphrase").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "storePassphrase must be redacted in full snapshot"
        );
        assert_eq!(
            matrix.get("deviceId").and_then(|v| v.as_str()),
            Some("DEVICE"),
            "deviceId is identity-linked, not secret — preserve"
        );
        assert_eq!(
            matrix.get("homeserverUrl").and_then(|v| v.as_str()),
            Some("https://matrix.example.com"),
            "non-secret fields preserved"
        );

        // raw text intentionally not served via WS — clients use parsed/config.
        assert!(
            response.get("raw").is_some_and(|v| v.is_null()),
            "raw text must not be served via config.get"
        );

        // parsed view must also be redacted
        let parsed_matrix = response
            .get("parsed")
            .and_then(|c| c.get("matrix"))
            .expect("parsed matrix subtree");
        assert_eq!(
            parsed_matrix.get("accessToken").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "parsed view must redact accessToken"
        );

        // Per-key query must redact too
        let by_key = handle_config_get(Some(&json!({"key": "matrix.accessToken"})))
            .expect("config.get with key");
        assert_eq!(
            by_key.get("value").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "per-key lookup must redact secrets"
        );

        // Non-secret per-key lookup unchanged
        let by_key = handle_config_get(Some(&json!({"key": "matrix.deviceId"})))
            .expect("config.get with non-secret key");
        assert_eq!(by_key.get("value").and_then(|v| v.as_str()), Some("DEVICE"));

        crate::config::clear_cache();
    }

    /// `config.set` / `config.apply` / `config.patch` echo the resulting
    /// config in the response. Without redaction, a caller patching a
    /// benign field could read existing plaintext secrets via the
    /// returned `config` object — even though `config.get` is now
    /// scrubbed. This test pins the contract: the response config must
    /// be redacted on all three write paths.
    #[test]
    fn test_handle_config_write_redacts_response_payload() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = crate::test_support::env::ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        fs::write(
            &path,
            r#"{
                matrix: {
                    accessToken: "existing-token-must-not-leak",
                    password: "existing-password-must-not-leak",
                    deviceId: "DEVICE",
                    homeserverUrl: "https://matrix.example.com"
                }
            }"#,
        )
        .expect("write config");
        env.set("CARAPACE_CONFIG_PATH", path.display().to_string());
        crate::config::clear_cache();

        let snapshot = read_config_snapshot();
        let base_hash = snapshot.hash.clone().expect("hash present");

        // config.patch with an unrelated field should NOT echo back the
        // existing plaintext secrets in the response.
        let patch_raw = r#"{matrix:{encrypted:false}}"#;
        let response = handle_config_patch(Some(&json!({
            "raw": patch_raw,
            "baseHash": base_hash,
        })))
        .expect("config.patch should succeed");
        let response_matrix = response
            .get("config")
            .and_then(|c| c.get("matrix"))
            .expect("response config.matrix");
        assert_eq!(
            response_matrix.get("accessToken").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "config.patch response must not echo existing accessToken"
        );
        assert_eq!(
            response_matrix.get("password").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "config.patch response must not echo existing password"
        );
        assert_eq!(
            response_matrix.get("deviceId").and_then(|v| v.as_str()),
            Some("DEVICE"),
            "protected non-secret identity field is unchanged"
        );
        assert_eq!(
            response_matrix.get("encrypted").and_then(|v| v.as_bool()),
            Some(false),
            "non-secret field reflects the patch"
        );

        crate::config::clear_cache();

        // Also exercise config.set with an explicit object containing a
        // secret-named field — it must come back redacted.
        let snapshot = read_config_snapshot();
        let base_hash = snapshot.hash.clone().expect("hash present");
        let set_raw = r#"{
            matrix: {
                accessToken: "existing-token-must-not-leak",
                password: "existing-password-must-not-leak",
                deviceId: "DEVICE",
                homeserverUrl: "https://matrix.example.com",
                encrypted: false
            }
        }"#;
        let response = handle_config_set(Some(&json!({
            "raw": set_raw,
            "baseHash": base_hash,
        })))
        .expect("config.set should succeed");
        let response_matrix = response
            .get("config")
            .and_then(|c| c.get("matrix"))
            .expect("response config.matrix");
        assert_eq!(
            response_matrix.get("accessToken").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "config.set response must not echo accessToken even when the caller supplied it"
        );
        assert_eq!(
            response_matrix.get("password").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "config.set response must not echo password even when the caller supplied it"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_config_write_rejects_protected_matrix_paths() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = crate::test_support::env::ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        fs::write(
            &path,
            r#"{
                matrix: {
                    accessToken: "token",
                    password: "password",
                    storePassphrase: "passphrase",
                    deviceId: "DEVICE",
                    homeserverUrl: "https://matrix.example.com",
                    userId: "@cara:example.com"
                }
            }"#,
        )
        .expect("write config");
        env.set("CARAPACE_CONFIG_PATH", path.display().to_string());
        crate::config::clear_cache();

        let replacement = r#"{
            matrix: {
                accessToken: "changed",
                password: "password",
                storePassphrase: "passphrase",
                deviceId: "DEVICE",
                homeserverUrl: "https://matrix.example.com",
                userId: "@cara:example.com"
            }
        }"#;
        for (method, call) in [
            (
                "config.set",
                handle_config_set
                    as fn(Option<&serde_json::Value>) -> Result<serde_json::Value, ErrorShape>,
            ),
            (
                "config.apply",
                handle_config_apply
                    as fn(Option<&serde_json::Value>) -> Result<serde_json::Value, ErrorShape>,
            ),
        ] {
            let snapshot = read_config_snapshot();
            let base_hash = snapshot.hash.clone().expect("hash present");
            let err = call(Some(&json!({
                "raw": replacement,
                "baseHash": base_hash,
            })))
            .expect_err("protected Matrix replacement must be rejected");
            assert_eq!(
                err.code, ERROR_INVALID_REQUEST,
                "{method} must protect Matrix"
            );
        }

        for (label, update) in [
            ("accessToken", r#"{matrix:{accessToken:"changed"}}"#),
            ("password", r#"{matrix:{password:"changed"}}"#),
            ("storePassphrase", r#"{matrix:{storePassphrase:"changed"}}"#),
            ("deviceId", r#"{matrix:{deviceId:"CHANGED"}}"#),
            (
                "homeserverUrl",
                r#"{matrix:{homeserverUrl:"https://evil.example.com"}}"#,
            ),
            ("userId", r#"{matrix:{userId:"@evil:example.com"}}"#),
        ] {
            let snapshot = read_config_snapshot();
            let base_hash = snapshot.hash.clone().expect("hash present");
            let err = handle_config_patch(Some(&json!({
                "raw": update,
                "baseHash": base_hash,
            })))
            .expect_err("protected Matrix patch must be rejected");
            assert_eq!(err.code, ERROR_INVALID_REQUEST, "{label} must be protected");
            assert!(
                err.message.contains("protected configuration"),
                "{label} should report protected path"
            );
        }

        crate::config::clear_cache();
    }

    /// `config.patch` against a corrupted on-disk file would
    /// otherwise merge `Null` with the patch and silently rewrite
    /// the file with only the patch contents — destroying the
    /// operator's broken-but-recoverable original. The handler
    /// explicitly refuses to patch a parsed-as-Null base and tells
    /// the operator to fix the file or use config.set.
    #[test]
    fn test_handle_config_patch_refuses_unparseable_base() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = crate::test_support::env::ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        // Intentionally invalid JSON5 — opening brace + unbalanced.
        let original = "{ this is not valid json5";
        fs::write(&path, original).expect("write corrupt config");
        env.set("CARAPACE_CONFIG_PATH", path.display().to_string());
        crate::config::clear_cache();

        // base hash matches the actual file contents; the corruption
        // alone should be enough to refuse.
        let base_hash = sha256_hex(original);
        let result = handle_config_patch(Some(&json!({
            "raw": "{matrix:{deviceId:'D'}}",
            "baseHash": base_hash,
        })));
        let err = result.expect_err("patch on unparseable base must be refused");
        assert!(
            err.message.contains("unparseable base"),
            "expected refusal message, got: {}",
            err.message
        );

        // Verify the on-disk file is unchanged.
        let after = fs::read_to_string(&path).expect("read");
        assert_eq!(after, original, "patch must not touch unparseable file");

        crate::config::clear_cache();
    }

    /// Direct test for `update_config_file` against an unparseable
    /// base. The merge variant must reject loudly rather than build
    /// a fresh `{}` and silently clobber the operator's broken file.
    /// This pins the inner guard from below the WS handlers — a
    /// future refactor that bypasses `handle_config_patch` (e.g.
    /// `cara config set` going direct via `update_config_file`)
    /// must not regress to "treat parse failure as no existing
    /// config".
    #[test]
    fn test_update_config_file_refuses_unparseable_base() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        let original = "{ this is not valid json5";
        fs::write(&path, original).expect("write corrupt base");

        let result = update_config_file(&path, |value| {
            value
                .as_object_mut()
                .expect("merge sees object")
                .insert("foo".to_string(), json!("bar"));
            Ok(())
        });
        let err = result.expect_err("update_config_file must refuse corrupt base");
        assert!(
            err.contains("unparseable base"),
            "expected refusal message, got: {err}"
        );

        let after = fs::read_to_string(&path).expect("read");
        assert_eq!(
            after, original,
            "update_config_file must leave a corrupt file untouched"
        );
    }

    /// Same guard via `try_update_config_file`. `try_` callers also
    /// must not silently clobber an unparseable base on a no-op
    /// update.
    #[test]
    fn test_try_update_config_file_refuses_unparseable_base() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("carapace.json5");
        let original = "{ this is not valid json5";
        fs::write(&path, original).expect("write corrupt base");

        let result =
            try_update_config_file(&path, |_value| Ok::<_, String>(ConfigUpdateOutcome::NoOp));
        let err = result.expect_err("try_update_config_file must refuse corrupt base");
        assert!(
            err.contains("unparseable base"),
            "expected refusal message, got: {err}"
        );

        let after = fs::read_to_string(&path).expect("read");
        assert_eq!(
            after, original,
            "try_update_config_file must leave a corrupt file untouched"
        );
    }

    /// Pin the REST `PersistConfigError → StatusCode` mapping. The
    /// `ConflictingBaseHash` arm must be 409 (client-side race);
    /// `Other` must be 500 (server fault). A regression that
    /// collapses both into 500 would lose the
    /// "re-read-and-retry" affordance for callers; collapsing both
    /// into 409 would mask real I/O failures as conflicts.
    #[test]
    fn test_persist_config_error_http_status() {
        use axum::http::StatusCode;
        assert_eq!(
            PersistConfigError::ConflictingBaseHash("drift".to_string()).http_status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            PersistConfigError::Other("io error".to_string()).http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// `config.reload` returns ERROR_UNAVAILABLE when the hot-reload bridge
    /// is not running. The bridge sets `reload_command_tx` on
    /// `WsServerState` once it spawns; without it, the handler refuses to
    /// process the request rather than installing a payload directly (which
    /// would skip provider validation).
    #[tokio::test]
    async fn test_handle_config_reload_errors_when_bridge_not_running() {
        let state = WsServerState::new(WsServerConfig::default());
        // No `set_reload_command_tx(Some(...))` here — bridge never spawned.

        let result = handle_config_reload(&state).await;

        let err = result.expect_err("must fail without a bridge");
        assert!(
            err.message.contains("config-reload bridge is not running"),
            "got: {}",
            err.message
        );
    }

    /// `config.reload` reports a generic ERROR_UNAVAILABLE when the bridge's
    /// load fails. The bridge's raw error message (potentially containing
    /// file paths, OS errnos, and parser positions) is logged server-side
    /// but kept out of the WS response, so error-aggregation pipelines
    /// don't unintentionally surface filesystem layout to less-privileged
    /// log consumers.
    #[tokio::test]
    async fn test_handle_config_reload_surfaces_bridge_load_error() {
        use crate::server::startup::{ReloadCommand, ReloadCommandResult};

        let state = WsServerState::new(WsServerConfig::default());
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(1);
        state.set_reload_command_tx(Some(command_tx));

        // Stand-in bridge: respond with a synthetic LoadError that includes
        // a path the WS response must NOT leak.
        let bridge = tokio::spawn(async move {
            let cmd = command_rx.recv().await.expect("bridge receives command");
            let _ = cmd.respond_to.send(ReloadCommandResult::LoadError(
                "/etc/carapace/config.json5: parse failed at line 1".to_string(),
            ));
        });

        let result = handle_config_reload(&state).await;
        bridge.await.expect("bridge task joins");

        let err = result.expect_err("LoadError must surface as Err");
        assert!(
            !err.message.contains("config.json5") && !err.message.contains("/etc/carapace"),
            "WS response must not leak the raw load-error path: {}",
            err.message
        );
        assert!(
            err.message.contains("config reload failed") && err.message.contains("server logs"),
            "WS response must point operators at server logs: {}",
            err.message
        );
    }

    /// `config.reload` returns ok+ERROR_UNAVAILABLE based on the bridge's
    /// outcome. `Reverted` (no provider in new config) maps to an error
    /// response that names the rejection reason; `Applied` maps to ok with
    /// the mode field populated from whatever the handler resolved.
    #[tokio::test]
    async fn test_handle_config_reload_maps_bridge_outcomes_to_responses() {
        use crate::server::startup::{ReloadCommand, ReloadCommandResult};

        // Applied path → Ok response with mode field set.
        {
            let state = WsServerState::new(WsServerConfig::default());
            let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(1);
            state.set_reload_command_tx(Some(command_tx));
            let bridge = tokio::spawn(async move {
                let cmd = command_rx.recv().await.expect("command received");
                // Echo the mode label the handler resolved so the assertion
                // pins the round-trip without depending on whatever
                // gateway.reload.mode the ambient on-disk config carries.
                let label = crate::config::watcher::mode_label(&cmd.mode).to_string();
                let _ = cmd.respond_to.send(ReloadCommandResult::Applied {
                    warnings: vec!["a: warn-one".to_string()],
                });
                label
            });
            let result = handle_config_reload(&state).await;
            let resolved_label = bridge.await.unwrap();
            let value = result.expect("Applied → Ok");
            assert_eq!(value["ok"], true);
            assert_eq!(value["mode"], serde_json::Value::String(resolved_label));
            // Warnings from the bridge must round-trip into the response so
            // clients can surface non-fatal validation issues to the operator.
            assert_eq!(
                value["warnings"],
                serde_json::json!(["a: warn-one"]),
                "Applied warnings must be forwarded to the WS response"
            );
        }

        // Reverted path → Err with provider-rejection message.
        {
            let state = WsServerState::new(WsServerConfig::default());
            let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(1);
            state.set_reload_command_tx(Some(command_tx));
            let bridge = tokio::spawn(async move {
                let cmd = command_rx.recv().await.expect("command received");
                let _ = cmd.respond_to.send(ReloadCommandResult::Reverted);
            });
            let result = handle_config_reload(&state).await;
            bridge.await.unwrap();
            let err = result.expect_err("Reverted → Err");
            assert!(
                err.message.contains("no LLM provider"),
                "Reverted reason must surface: {}",
                err.message
            );
        }
    }
}
