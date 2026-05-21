//! Matrix inbound dead-letter queue.
//!
//! This module owns encrypted DLQ envelope encoding/decoding, replay,
//! quarantine of undecodable lines, and store-rekey recovery. The envelope
//! constants below are persisted wire-format commitments: changing AAD,
//! HKDF info, or envelope versions requires a new reader branch and pinned
//! compatibility tests.

use super::*;
use matrix_sdk::ruma::{EventId, RoomId, UserId};

const MATRIX_INBOUND_DLQ_INFO: &[u8] = b"carapace-matrix-inbound-dlq-v1";
// AAD for the AES-GCM seal of DLQ records. Note: this string lacks the
// `carapace-` application prefix that `MATRIX_STORE_INFO` and
// `MATRIX_INBOUND_DLQ_INFO` carry. The prefix omission was the original
// shape committed and is now locked in: the AAD is part of the GCM
// authentication tag of every on-disk DLQ record, so changing the
// constant value is a wire-format break that would invalidate every
// existing encrypted DLQ. A future v2 envelope can adopt the
// `carapace-` prefix; until then, this departure is intentional.
const MATRIX_INBOUND_DLQ_AAD: &[u8] = b"matrix-inbound-dlq-v1";
/// On-disk envelope version for `MatrixEncryptedInboundDlqRecord`.
/// Bumping the codec (new field, different encoding, different AAD)
/// requires bumping this AND the decode-time gate together. Pinning a
/// named constant keeps writer and reader in sync — two raw `1` literals
/// at separate sites would let one drift silently and either reject our
/// own DLQ records or silently mis-decode them with stale params.
///
/// v1 (legacy): HKDF-SHA256 over `(passphrase, installation_id)` with
///   `MATRIX_INBOUND_DLQ_INFO` as the info string. Fast (microseconds
///   per derivation) — vulnerable to offline brute-force on
///   `CARAPACE_CONFIG_PASSWORD` if a local attacker has read access to
///   `state_dir/matrix/inbound_dlq.jsonl` plus
///   `state_dir/installation_id`.
/// v2 (current): Argon2id (memory-hard KDF with work factor)
///   over `(passphrase, installation_id)` via
///   `crate::crypto::derive_key_argon2id`. The derivation cost
///   matches the existing config-secret seal layer. Brute-force on
///   `CARAPACE_CONFIG_PASSWORD` is now memory-bound rather than
///   HKDF-fast.
///
/// Migration: writers always emit v2. Readers accept v1 OR v2 so
/// existing on-disk records keep decoding through the upgrade —
/// operators do not need to drain the DLQ before bumping carapace.
const MATRIX_INBOUND_DLQ_ENVELOPE_VERSION: u8 = 2;
/// Legacy envelope version. The v1 read path is retained so existing
/// on-disk records (HKDF-derived keys) continue to decode after
/// upgrade. Once an operator has fully drained the DLQ, no v1
/// records remain on disk and the legacy branch is unreachable;
/// it stays in the source for cross-version compatibility within
/// the supported upgrade window.
const MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY: u8 = 1;

fn dlq_crypto_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::DlqCrypto(DlqCryptoFailure::Other(detail.into()))
}

fn dlq_crypto_operation_failed(operation: &'static str) -> MatrixError {
    dlq_crypto_failed(format!("{operation} failed"))
}

fn dlq_crypto_config_unavailable(version: u8) -> MatrixError {
    MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable {
        version: Some(version),
        context: None,
    })
}

fn dlq_crypto_config_unavailable_with_context(
    version: Option<u8>,
    context: impl Into<String>,
) -> MatrixError {
    MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable {
        version,
        context: Some(context.into()),
    })
}

fn legacy_dlq_envelope_refused(detail: impl Into<String>) -> MatrixError {
    MatrixError::LegacyDlqEnvelopeRefused(detail.into())
}

fn dlq_io_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::DlqIo(detail.into())
}

fn dlq_serialization_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::DlqSerialization(detail.into())
}

fn dlq_dispatch_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::DlqDispatchFailure(detail.into())
}

fn dlq_cap_saturation(detail: impl Into<String>) -> MatrixError {
    MatrixError::DlqCapSaturation(detail.into())
}

async fn sync_dlq_parent_dir_or_err(path: &Path) -> Result<(), MatrixError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_dlq_parent_dir_or_err_blocking(&path))
        .await
        .map_err(|err| dlq_io_failed(format!("Matrix inbound DLQ parent-dir fsync task: {err}")))?
}

fn sync_dlq_parent_dir_or_err_blocking(path: &Path) -> Result<(), MatrixError> {
    crate::paths::sync_parent_dir_blocking(path)
        .map_err(|err| dlq_io_failed(format!("fsync Matrix inbound DLQ parent dir: {err}")))
}

/// One inbound Matrix event parked on the dead-letter queue after a
/// dispatch failure. The `text` field holds *decrypted* room body text
/// when the source room is encrypted, so:
///
/// 1. `Debug` is hand-rolled to elide the body — a stray
///    `tracing::debug!(?record, ...)` would otherwise print E2EE
///    plaintext into stdout/journal/`RedactingWriter` (which only
///    matches OAuth/bearer/recovery-key shapes, not free-form text).
/// 2. `Drop` zeroizes `text` and the PII identifiers on the way out so a
///    leaked heap allocation cannot recover decrypted body text or Matrix
///    user/room/event ids with a memory inspector. The identifier fields are
///    stored as strings here because ruma owned ids do not implement
///    `Zeroize`; deserialization below still validates the persisted boundary
///    through the ruma typed identifiers before re-entering the runtime.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct MatrixInboundDlqRecord {
    event_id: String,
    room_id: String,
    sender_id: String,
    text: String,
    received_at: i64,
}

impl MatrixInboundDlqRecord {
    pub(super) fn new(
        event_id: &EventId,
        room_id: &RoomId,
        sender_id: &UserId,
        text: impl Into<String>,
        received_at: i64,
    ) -> Self {
        Self {
            event_id: event_id.to_string(),
            room_id: room_id.to_string(),
            sender_id: sender_id.to_string(),
            text: text.into(),
            received_at,
        }
    }
}

impl<'de> Deserialize<'de> for MatrixInboundDlqRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            event_id: String,
            room_id: String,
            sender_id: String,
            text: String,
            received_at: i64,
        }

        let wire = Wire::deserialize(deserializer)?;
        <&EventId>::try_from(wire.event_id.as_str()).map_err(serde::de::Error::custom)?;
        <&RoomId>::try_from(wire.room_id.as_str()).map_err(serde::de::Error::custom)?;
        <&UserId>::try_from(wire.sender_id.as_str()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            event_id: wire.event_id,
            room_id: wire.room_id,
            sender_id: wire.sender_id,
            text: wire.text,
            received_at: wire.received_at,
        })
    }
}

impl std::fmt::Debug for MatrixInboundDlqRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixInboundDlqRecord")
            .field("event_id", &self.event_id)
            .field("room_id", &self.room_id)
            .field("sender_id", &self.sender_id)
            .field("text", &format_args!("<elided {} bytes>", self.text.len()))
            .field("received_at", &self.received_at)
            .finish()
    }
}

impl Drop for MatrixInboundDlqRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Each owned DLQ record clone zeroizes its own fields. Strings cloned
        // out of the record for dispatch, logging, or audit are separately
        // owned by those paths and cannot be scrubbed by this Drop.
        self.event_id.zeroize();
        self.room_id.zeroize();
        self.sender_id.zeroize();
        self.text.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MatrixEncryptedInboundDlqRecord {
    pub(super) version: u8,
    pub(super) nonce: String,
    pub(super) ciphertext: String,
}

pub(crate) fn matrix_inbound_dlq_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("inbound_dlq.jsonl")
}

pub(super) fn matrix_inbound_dlq_rekey_backup_path(state_dir: &Path) -> PathBuf {
    matrix_inbound_dlq_path(state_dir).with_extension("jsonl.pre-rekey")
}

fn matrix_inbound_dlq_rekey_temp_path(state_dir: &Path) -> PathBuf {
    matrix_inbound_dlq_path(state_dir).with_extension("jsonl.rekeyed")
}

pub(super) fn matrix_inbound_dlq_quarantine_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("inbound_dlq.corrupt.jsonl")
}

/// Cap on the on-disk quarantine file size. Quarantine is for forensic
/// recovery of lines the runtime can't decode (key-mismatch wave,
/// envelope-version drift). Once full, additional corrupt lines are no
/// more recoverable than the ones already there — and an attacker
/// driving sustained corruption (or repeat operator key rotations
/// between DLQ floods) could otherwise fill the disk silently. 10 MB
/// is well above the legitimate post-rotation forensic window for a
/// daemon at typical message rates.
pub(super) const MATRIX_DLQ_QUARANTINE_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Append undecodable DLQ lines to a sibling quarantine file
/// (`inbound_dlq.corrupt.jsonl`) so the live DLQ can drain. The lines
/// are preserved verbatim — they failed to decode, so re-encoding
/// would lose the original on-disk form needed for forensic recovery.
pub(super) async fn append_matrix_inbound_dlq_quarantine(
    state_dir: &Path,
    lines: &[String],
) -> Result<(), MatrixError> {
    let path = matrix_inbound_dlq_quarantine_path(state_dir);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| dlq_io_failed(format!("create Matrix DLQ quarantine dir: {err}")))?;
    }

    // Refuse to grow the quarantine file past
    // MATRIX_DLQ_QUARANTINE_MAX_BYTES. Drop the new lines with a warn
    // — the on-disk evidence of earlier corruption survives, and the
    // operator can rotate / archive / triage before clearing the cap.
    //
    // The check accounts for the size of the incoming batch (existing
    // + append ≤ cap), not just the existing size. A batch that would
    // bring the file size past the cap also gets dropped, with a
    // single warn covering both the existing-overflow and incoming-
    // overflow cases.
    let incoming_bytes = lines
        .iter()
        .map(|line| line.len().saturating_add(1)) // +1 for trailing '\n'
        .fold(0u64, |acc, n| acc.saturating_add(n as u64));
    let line_count = lines.len();
    let blob = lines
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let path_owned = path.clone();
    let state_dir_owned = state_dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let _quarantine_lock = crate::sessions::file_lock::FileLock::acquire(&path_owned)
            .map_err(|err| dlq_io_failed(format!("lock Matrix DLQ quarantine: {err}")))?;
        if let Ok(metadata) = std::fs::metadata(&path_owned) {
            let projected = metadata.len().saturating_add(incoming_bytes);
            if projected > MATRIX_DLQ_QUARANTINE_MAX_BYTES {
                warn!(
                    path = %path_owned.display(),
                    quarantine_bytes = metadata.len(),
                    incoming_bytes,
                    projected,
                    cap = MATRIX_DLQ_QUARANTINE_MAX_BYTES,
                    dropped_lines = line_count,
                    "Matrix DLQ quarantine file at cap; dropping new corrupt lines. \
                     Archive or rotate the existing quarantine before clearing the cap."
                );
                // SECURITY: a tracing-warn alone is easy to lose under
                // sustained corruption. Emit a durable audit record so
                // the operator's explicit `policy=Refuse` choice does
                // not silently lose records without a grep-able audit
                // trail. Same durability tier as the allowlist-drift
                // drop a few hundred lines down — if the audit write
                // fails, surface the failure so the caller can keep
                // the records in the live DLQ instead of acknowledging
                // a drop we never durably recorded.
                crate::logging::audit::audit_durable_for_state_dir(
                    state_dir_owned.clone(),
                    crate::logging::audit::AuditEvent::MatrixInboundDlqQuarantineCapDropped {
                        dropped_lines: line_count,
                        incoming_bytes,
                        existing_quarantine_bytes: metadata.len(),
                        cap_bytes: MATRIX_DLQ_QUARANTINE_MAX_BYTES,
                    },
                )
                .map_err(|err| {
                    dlq_io_failed(format!(
                        "audit Matrix DLQ quarantine cap-drop: {err}; refusing to drop records without durable forensic evidence"
                    ))
                })?;
                return Ok(());
            }
        } else if incoming_bytes > MATRIX_DLQ_QUARANTINE_MAX_BYTES {
            warn!(
                path = %path_owned.display(),
                incoming_bytes,
                cap = MATRIX_DLQ_QUARANTINE_MAX_BYTES,
                dropped_lines = line_count,
                "Matrix DLQ quarantine first-write batch exceeds cap; dropping"
            );
            // SECURITY: see companion comment in the existing-file
            // branch — same durable-audit requirement applies to the
            // first-write batch that itself exceeds the cap.
            crate::logging::audit::audit_durable_for_state_dir(
                state_dir_owned.clone(),
                crate::logging::audit::AuditEvent::MatrixInboundDlqQuarantineCapDropped {
                    dropped_lines: line_count,
                    incoming_bytes,
                    existing_quarantine_bytes: 0,
                    cap_bytes: MATRIX_DLQ_QUARANTINE_MAX_BYTES,
                },
            )
            .map_err(|err| {
                dlq_io_failed(format!(
                    "audit Matrix DLQ quarantine first-write cap-drop: {err}; refusing to drop records without durable forensic evidence"
                ))
            })?;
            return Ok(());
        }
        // SECURITY: quarantine carries the same payloads as the live DLQ
        // (encrypted-record envelopes when matrix.encrypted=true, raw event
        // text otherwise). Owner-only mode mirrors the live DLQ writer at
        // `append_matrix_inbound_dlq_line_blocking` so other local users
        // can't read messages that the live DLQ deliberately keeps private.
        // Both first-create and existing-file branches enforce 0o600; if a
        // pre-existing file is wider, force it back.
        let was_first_write = !path_owned.exists();
        let mut file = open_matrix_dlq_quarantine_owner_only(&path_owned)
            .map_err(|err| dlq_io_failed(format!("open Matrix DLQ quarantine: {err}")))?;
        ensure_matrix_dlq_quarantine_owner_only(&file).map_err(|err| {
            dlq_io_failed(format!("chmod Matrix DLQ quarantine: {err}"))
        })?;
        use std::io::Write;
        file.write_all(blob.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|err| {
                dlq_io_failed(format!("write Matrix DLQ quarantine: {err}"))
            })?;
        // First-time creation requires a parent-dir fsync so the new dirent
        // survives a power loss. The live DLQ rewrite that follows is
        // already fsynced; without this the quarantine sibling could be
        // lost while the rewrite landed, silently dropping corrupt records
        // we promised to preserve for forensic recovery.
        if was_first_write {
            crate::paths::sync_parent_dir_blocking(&path_owned).map_err(|err| {
                dlq_io_failed(format!("fsync Matrix DLQ quarantine dir: {err}"))
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|err| dlq_io_failed(format!("Matrix DLQ quarantine task: {err}")))?
}

#[cfg(unix)]
pub(super) fn open_matrix_dlq_quarantine_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    // SECURITY: O_NOFOLLOW + O_NONBLOCK. O_NOFOLLOW prevents a same-
    // uid attacker from pre-planting a symlink at the quarantine
    // path and redirecting our (encrypted) DLQ-corruption writes
    // through it. O_NONBLOCK additionally prevents
    // `O_CREAT | O_WRONLY | O_APPEND` from blocking when the dirent
    // is a planted FIFO with no reader — the post-open file-type
    // refusal below only fires AFTER open(2) returns. Same lesson
    // as the B99 sweep; this site was missed.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened_metadata = file.metadata()?;
    let file_type = opened_metadata.file_type();
    if !file_type.is_file()
        || file_type.is_symlink()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Matrix DLQ quarantine path is not a regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(super) fn open_matrix_dlq_quarantine_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    // SECURITY: pre-check via symlink_metadata when the file exists
    // to refuse a symlink pre-plant. Encrypted Matrix state is
    // refused on non-Unix per `ensure_encrypted_matrix_state_supported_on_platform`,
    // so the residual race window here is acceptable.
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Matrix DLQ quarantine path is a symlink, refusing to follow: {}",
                    path.display()
                ),
            ));
        }
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[cfg(unix)]
pub(super) fn ensure_matrix_dlq_quarantine_owner_only(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // SECURITY: operate against the opened file (fd-based) rather
    // than the path. Path-based `std::fs::metadata` /
    // `set_permissions` both follow symlinks on Linux; a same-uid
    // attacker who atomically swapped the dirent between open and
    // this chmod could see us chmod the wrong file (relevant when
    // the daemon runs as root). `open_matrix_dlq_quarantine_owner_only`
    // above used O_NOFOLLOW + post-open file-type revalidation; this
    // helper completes the TOCTOU-safe pattern by operating only on
    // the fd we just validated.
    let metadata = file.metadata()?;
    let mut permissions = metadata.permissions();
    if permissions.mode() & 0o777 != 0o600 {
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn ensure_matrix_dlq_quarantine_owner_only(
    _file: &std::fs::File,
) -> std::io::Result<()> {
    Ok(())
}

pub(super) async fn append_matrix_inbound_dlq(
    state_dir: &Path,
    config: &MatrixConfig,
    state: Arc<RwLock<MatrixRuntimeState>>,
    record: &MatrixInboundDlqRecord,
) -> Result<(), MatrixError> {
    let path = matrix_inbound_dlq_path(state_dir);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| dlq_io_failed(format!("create Matrix inbound DLQ dir: {err}")))?;
    }

    // At-cap latch: under sustained inbound-failure flood (downstream
    // channel outage, agent pipeline storm) every dispatch failure
    // here would otherwise pay a full ~MiB-class `tokio::fs::read_to_string`
    // under `dlq_io_lock` to re-confirm the cap that was already
    // confirmed on the previous event. Short-circuit cheaply via the
    // latch BEFORE acquiring the io lock, the dlq_keys cache, or
    // serializing the record. The latch TTL bounds the worst-case
    // false-block window if a replay-rewrite crashes between
    // cap-confirm and a fresh stamp.
    {
        let guard = state.read();
        if let Some(since) = guard.inbound_dlq_at_cap_since_ms {
            let elapsed = now_millis().saturating_sub(since);
            if elapsed < MATRIX_INBOUND_DLQ_AT_CAP_LATCH_TTL_MS {
                drop(guard);
                state.write().record_inbound_dlq_append_failure(format!(
                    "Matrix inbound DLQ at {}-record cap (latched, observed {elapsed}ms ago); \
                     dropping new dispatch failures until the queue drains",
                    MATRIX_INBOUND_DLQ_MAX_RECORDS,
                ));
                return Err(dlq_cap_saturation(
                    "Matrix inbound DLQ at size cap (latched); record dropped".to_string(),
                ));
            }
        }
    }

    // Route the encode through the daemon-lifetime DLQ key cache.
    // Without this, every concurrent inbound dispatch failure pays
    // a fresh ~100 ms Argon2id derivation while holding
    // `dlq_io_lock` — exactly the per-record cost the cache was
    // added to eliminate. The replay loop already uses the cache;
    // append must too.
    let dlq_keys = state.read().dlq_keys();
    let key = if config.encrypted() {
        Some(dlq_keys.ensure_v2(state_dir, config)?)
    } else {
        None
    };
    let serialized = encode_matrix_inbound_dlq_record_with_key(key, record)?;
    // Cap check and (if below cap) the append both run under the
    // dlq_io_lock. The cap-drop branch atomically stamps BOTH the
    // at-cap latch AND the durability error string under a single
    // `state.write()` so a future cancellation between those two
    // mutations cannot leave the runtime view inconsistent (B131).
    //
    // The durable audit emission is HOISTED out of the lock-held
    // scope: the spawn_blocking + .await inside the lock would
    // otherwise serialize every concurrent appender behind the
    // audit write under a sustained dispatch-failure flood. The
    // at-cap latch we set earlier already short-circuits subsequent
    // appenders at the cheap pre-lock check, so the audit emission
    // is intentionally fire-and-await OUTSIDE the lock.
    let lock = state.read().dlq_io_lock();
    let cap_drop_count = {
        let _guard = lock.lock().await;
        // SECURITY: cap DLQ size before appending. The cheapest
        // line-count check on a JSONL file is reading existing
        // length; we can short-circuit by checking the file size
        // against a conservative per-record floor (records are at
        // minimum a few hundred bytes). Use line count for accuracy
        // under the lock.
        let count = matrix_inbound_dlq_line_count(&path).await?.unwrap_or(0);
        if count < MATRIX_INBOUND_DLQ_MAX_RECORDS {
            // Below cap — append under the same guard.
            let result = append_matrix_inbound_dlq_line(&path, serialized).await;
            if result.is_ok() {
                state.write().clear_inbound_dlq_durability_error();
            }
            return result;
        }
        // At cap. Stamp BOTH state fields under ONE state.write()
        // so the runtime view (`at_cap_since_ms` + `last_error`)
        // stays consistent across cancellation between them.
        {
            let mut s = state.write();
            s.inbound_dlq_at_cap_since_ms = Some(now_millis());
            s.record_inbound_dlq_append_failure(format!(
                "Matrix inbound DLQ at {} reached {MATRIX_INBOUND_DLQ_MAX_RECORDS}-record cap; \
                 dropping new dispatch failures until the queue drains",
                path.display()
            ));
        }
        warn!(
            path = %path.display(),
            lines = count,
            limit = MATRIX_INBOUND_DLQ_MAX_RECORDS,
            "Matrix inbound DLQ size cap reached; dropping record. \
             Operator action: fix the underlying inbound dispatch \
             failure (typically a misconfigured agent or downstream \
             channel). The DLQ drains automatically on the next \
             successful post-sync replay tick — no manual file action \
             is needed in the normal recovery path. If you must discard \
             records to clear backlog, stop the daemon first, then \
             truncate or remove inbound_dlq.jsonl; truncating while the \
             daemon is running races the DLQ rewrite path."
        );
        count
    }; // dlq_io_lock guard drops here — peer appenders can short-
       // circuit on the at-cap latch we just stamped without
       // serializing behind the audit emission below.

    // SECURITY/FORENSICS: emit a durable audit so a post-incident
    // query can correlate "channel went silent" with the exact
    // event-loss window. Matches the forensic tier of the
    // quarantine cap-drop audit (`MatrixInboundDlqQuarantineCapDropped`).
    // Uses the threaded `state_dir` parameter (B129) so the audit
    // lands in the same forensic stream as every other audit in
    // this function.
    let cap_drop_event = crate::logging::audit::AuditEvent::MatrixInboundDlqCapDropped {
        existing_lines: cap_drop_count as u64,
        cap_records: MATRIX_INBOUND_DLQ_MAX_RECORDS as u64,
    };
    let audit_state_dir = state_dir.to_path_buf();
    let audit_result = tokio::task::spawn_blocking(move || {
        crate::logging::audit::audit_durable_for_state_dir(audit_state_dir, cap_drop_event)
    })
    .await;
    match audit_result {
        Ok(Ok(())) => {}
        Ok(Err(audit_err)) => {
            tracing::warn!(
                error = %audit_err,
                "failed to emit durable audit for matrix_inbound_dlq_cap_dropped; \
                 tracing-warn above is the only forensic signal for this drop"
            );
        }
        Err(join_err) => {
            tracing::warn!(
                error = %join_err,
                "audit task for matrix_inbound_dlq_cap_dropped panicked or was cancelled"
            );
        }
    }
    Err(dlq_cap_saturation(
        "Matrix inbound DLQ at size cap; record dropped".to_string(),
    ))
}

/// Count lines in the DLQ file (best-effort). Returns `Ok(None)` when
/// the file doesn't exist (= queue is empty, no cap risk). Errors
/// otherwise are surfaced so the cap can fail-closed if the queue
/// state can't be determined.
///
/// Two-phase check: (1) `metadata().len()` is a syscall-only size
/// query that does no file content I/O; (2) only when the byte size
/// gets close to the cap (per-record-floor heuristic) do we fall back
/// to reading the file and counting newlines for an exact count. This
/// keeps the common hot-path call O(1) syscall instead of multi-MB of
/// content I/O — without that, every `append_matrix_inbound_dlq` would
/// hold the dlq_io_lock during a full file read for files near cap,
/// blocking concurrent appends for the duration of the read.
/// `O_NOFOLLOW`-and-regular-file opener for the Matrix inbound DLQ
/// file. Refuses to traverse a planted symlink — defends the replay
/// path against a same-uid attacker substituting an attacker-chosen
/// file for the DLQ JSONL stream.
#[cfg(unix)]
pub(super) async fn open_matrix_dlq_for_read_no_follow(
    path: &Path,
) -> std::io::Result<tokio::fs::File> {
    // O_NOFOLLOW + O_NONBLOCK: same lesson as the Batch-82/83 shared
    // helpers — O_NOFOLLOW alone protects against symlink traversal
    // but does NOT prevent open(2) from blocking indefinitely on a
    // FIFO planted at the dirent. The post-open `is_file()` check
    // below only runs after `open` returns. Regular files ignore
    // O_NONBLOCK so the happy path is unchanged; for a planted FIFO
    // with no writer, open returns immediately and the `is_file()`
    // check refuses it.
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).await?;
    let metadata = file.metadata().await?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "refusing to read Matrix inbound DLQ {}: opened path is a symlink",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(std::io::Error::other(format!(
            "refusing to read Matrix inbound DLQ {}: opened path is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(super) async fn open_matrix_dlq_for_read_no_follow(
    path: &Path,
) -> std::io::Result<tokio::fs::File> {
    // Path is operator-trusted: derived from `state_dir` config; not
    // user-supplied. Carapace is not an Actix app.
    tokio::fs::File::open(path).await // nosemgrep
}

pub(super) async fn matrix_inbound_dlq_line_count(
    path: &Path,
) -> Result<Option<usize>, MatrixError> {
    // Conservative per-record floor for the size heuristic. Encrypted
    // DLQ records (the common case for `matrix.encrypted=true`
    // deployments) are at minimum ~270 bytes: 12-byte AES-GCM nonce →
    // 16 base64 chars; plaintext `MatrixInboundDlqRecord` (event_id
    // ~50 chars + room_id ~30 + sender_id ~30 + text ≥1 + received_at
    // ~13 + JSON syntax) is ~150+ bytes; AES-GCM ciphertext + 16-byte
    // tag base64-encoded ≥222 chars; total JSON envelope ≥270 bytes.
    // Plaintext records (encrypted=false) can be intentionally tiny
    // in tests or after future codec tightening. Keep the heuristic
    // floor below the practical plaintext minimum so a 10k-line DLQ
    // cannot remain under the syscall-only byte threshold.
    const PER_RECORD_FLOOR_BYTES: u64 = 100;
    const CAP_BYTES_FLOOR: u64 =
        (MATRIX_INBOUND_DLQ_MAX_RECORDS as u64).saturating_mul(PER_RECORD_FLOOR_BYTES);
    // `symlink_metadata` does NOT follow symlinks — required because
    // the DLQ file lives in `state_dir/matrix/` which is 0o700 but
    // still reachable by a same-uid attacker (tool-call escape).
    // Without this, a planted symlink at `inbound-dlq.jsonl` redirects
    // the size probe to an attacker-chosen file; while AEAD decryption
    // protects record integrity, the substituted file's contents
    // still get copied verbatim into the quarantine artifact under
    // state_dir on decrypt failure.
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(dlq_io_failed(format!(
                "stat Matrix inbound DLQ for cap check {}: {err}",
                path.display()
            )))
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(dlq_io_failed(format!(
            "refusing to read Matrix inbound DLQ {}: path is a symlink",
            path.display()
        )));
    }

    // If the file size is well below cap × floor bytes, the cap can't
    // possibly be reached. Skip the content read entirely.
    let cap_bytes_floor = CAP_BYTES_FLOOR;
    if metadata.len() < cap_bytes_floor {
        // Below the floor → cannot exceed the cap. Return a count
        // sentinel of 0 to short-circuit the comparison; the cap path
        // only fires on `>= MATRIX_INBOUND_DLQ_MAX_RECORDS` so a 0
        // count is structurally safe.
        return Ok(Some(0));
    }

    // Possibly at-cap. Pay the full read for an accurate count — but
    // stream line-by-line with a per-line cap so a pathologically
    // large file (a planted regular file passing the floor check but
    // holding one huge newline-free line) doesn't OOM the daemon.
    // `tokio::io::Lines::next_line` would allocate the next line in
    // full before returning, undoing the cap we enforce in the replay
    // reader. Mirrors `read_matrix_inbound_dlq_lines_streaming`'s
    // bounded read_until pattern; same per-line cap constant.
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let file = match open_matrix_dlq_for_read_no_follow(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(dlq_io_failed(format!(
                "open Matrix inbound DLQ for cap check {}: {err}",
                path.display()
            )))
        }
    };
    let mut reader = tokio::io::BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    let line_cap = MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES + 1; // +1 for newline
    let mut count: usize = 0;
    loop {
        buf.clear();
        let bytes_read = (&mut reader)
            .take(line_cap as u64)
            .read_until(b'\n', &mut buf)
            .await
            .map_err(|err| {
                dlq_io_failed(format!(
                    "read Matrix inbound DLQ for cap check {}: {err}",
                    path.display()
                ))
            })?;
        if bytes_read == 0 {
            break;
        }
        // Fail closed if the cap was hit without a terminating newline.
        if bytes_read >= line_cap && buf.last().copied() != Some(b'\n') {
            return Err(dlq_cap_saturation(format!(
                "Matrix inbound DLQ {} contains a line exceeding {} bytes; refusing to load",
                path.display(),
                MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES
            )));
        }
        count = count.saturating_add(1);
        // Early-exit once we've crossed the cap threshold. The caller
        // only checks `>= MATRIX_INBOUND_DLQ_MAX_RECORDS`, so a
        // saturated count is sufficient signal.
        if count > MATRIX_INBOUND_DLQ_MAX_RECORDS {
            break;
        }
    }
    Ok(Some(count))
}

/// One classified outcome from the per-record decode in
/// `replay_matrix_inbound_dlq`. Lines that fail to decode are kept
/// verbatim in `Corrupt` so the rewrite path can preserve them on
/// disk for forensic recovery instead of silently dropping them.
pub(super) enum DlqReplayLine {
    Decoded {
        record: MatrixInboundDlqRecord,
        legacy_envelope_version: Option<u8>,
    },
    /// Permanently undecodable (corrupt ciphertext, wrong AAD,
    /// unknown envelope version, malformed JSON). Move to the
    /// quarantine file so the live DLQ can drain.
    Corrupt {
        raw: String,
        error: String,
        error_class: DlqReplayErrorClass,
    },
    /// Temporarily undecodable: the line is well-formed and likely
    /// recoverable, but a current configuration choice prevents
    /// decoding (e.g. `matrix.encrypted=false` with v1/v2 records
    /// still on disk from a prior `matrix.encrypted=true` run, so
    /// no AEAD key can be derived). Keep in the live DLQ; a
    /// subsequent replay tick under restored config drains them
    /// naturally.
    TemporarilyUndecodable {
        raw: String,
        error: String,
        error_class: DlqReplayErrorClass,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DlqReplayErrorClass {
    Dispatch,
    SessionHistory,
    Serialization,
    CryptoConfigUnavailable { version: Option<u8> },
    Crypto,
    CapSaturation,
    Io,
    LegacyRefused,
}

fn classify_dlq_replay_error(err: &MatrixError) -> DlqReplayErrorClass {
    match err {
        MatrixError::LegacyDlqEnvelopeRefused(_) => DlqReplayErrorClass::LegacyRefused,
        MatrixError::DlqIo(_) => DlqReplayErrorClass::Io,
        MatrixError::DlqCapSaturation(_) => DlqReplayErrorClass::CapSaturation,
        MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable { version, .. }) => {
            DlqReplayErrorClass::CryptoConfigUnavailable { version: *version }
        }
        MatrixError::DlqCrypto(_) | MatrixError::MissingStoreSecret => DlqReplayErrorClass::Crypto,
        MatrixError::DlqSerialization(_) => DlqReplayErrorClass::Serialization,
        MatrixError::SessionHistoryCorrupt(_) => DlqReplayErrorClass::SessionHistory,
        MatrixError::DlqDispatchFailure(_) => DlqReplayErrorClass::Dispatch,
        // Unreachable in normal replay operation: dispatch_matrix_dlq_record
        // converts downstream/auth/runtime failures into DlqDispatchFailure or
        // SessionHistoryCorrupt before the replay loop classifies them. Keeping
        // these arms exhaustive prevents a future MatrixError variant from
        // compiling without a deliberate DLQ aggregate classification; the
        // debug assertion catches any caller that bypasses the dispatch wrapper.
        MatrixError::InvalidConfigRoot
        | MatrixError::InvalidString { .. }
        | MatrixError::InvalidBool { .. }
        | MatrixError::InvalidStringArray { .. }
        | MatrixError::InvalidLength { .. }
        | MatrixError::InvalidUrl { .. }
        | MatrixError::AllowlistTooLarge { .. }
        | MatrixError::MissingHomeserverUrl
        | MatrixError::MissingUserId
        | MatrixError::MissingCredentials
        | MatrixError::MissingDeviceIdForTokenRestore
        | MatrixError::StoreKeyDerivation
        | MatrixError::InstallationId(_)
        | MatrixError::ClientBuild(_)
        | MatrixError::Auth(_)
        | MatrixError::AuthProbe(_)
        | MatrixError::AuthSessionUserMismatch { .. }
        | MatrixError::AuthSessionDeviceMismatch { .. }
        | MatrixError::AuthSessionMissingDeviceId
        | MatrixError::AuthTokenRevoked(_)
        | MatrixError::TokenPersistence(_)
        | MatrixError::RecoveryKeyRestoreFailed { .. }
        | MatrixError::CrossSigningBootstrapFailed(_)
        | MatrixError::EncryptedStateIo(_)
        | MatrixError::RecoveryStateProbeFailed(_)
        | MatrixError::RecoveryStateIo(_)
        | MatrixError::RecoveryConfigPrecondition(_)
        | MatrixError::RecoveryKeyPromotionRefused(_)
        | MatrixError::StartupFailed(_)
        | MatrixError::InterruptedRekey(_)
        | MatrixError::Clock(_)
        | MatrixError::NotConnected
        | MatrixError::UnsupportedRoom(_)
        | MatrixError::RoomNotFound(_)
        | MatrixError::SendFailed { .. }
        | MatrixError::SyncFailed(_)
        | MatrixError::SyncLoopGaveUp { .. }
        | MatrixError::VerificationFlowNotFound(_)
        | MatrixError::InvalidUserId(_)
        | MatrixError::DeviceNotFound { .. }
        | MatrixError::UserIdentityNotFound(_)
        | MatrixError::VerificationFlowNotReady { .. }
        | MatrixError::Verification(_)
        | MatrixError::VerificationTimeout(_)
        | MatrixError::CommandQueueFull
        | MatrixError::EncryptedStorePassphraseMismatch { .. }
        | MatrixError::VerificationCancelled { .. }
        | MatrixError::SendTerminal(_) => {
            debug_assert!(
                false,
                "unwrapped non-DLQ MatrixError reached DLQ replay classifier: {}",
                err.kind()
            );
            tracing::error!(
                kind = err.kind(),
                "unwrapped non-DLQ MatrixError reached DLQ replay classifier; \
                 preserving historical dispatch fallback"
            );
            DlqReplayErrorClass::Dispatch
        }
    }
}

fn dlq_replay_error_class_priority(class: DlqReplayErrorClass) -> u8 {
    match class {
        DlqReplayErrorClass::Dispatch => 0,
        DlqReplayErrorClass::SessionHistory => 1,
        DlqReplayErrorClass::Serialization => 2,
        // Policy refusal is an operator-actionable result, but it should not
        // hide concurrent crypto, capacity, or filesystem failures that affect
        // records beyond the intentionally refused legacy envelope.
        DlqReplayErrorClass::LegacyRefused => 3,
        DlqReplayErrorClass::CryptoConfigUnavailable { .. } => 4,
        DlqReplayErrorClass::Crypto => 4,
        DlqReplayErrorClass::CapSaturation => 5,
        DlqReplayErrorClass::Io => 6,
    }
}

fn merge_dlq_replay_error_class(
    current: &mut Option<DlqReplayErrorClass>,
    next: DlqReplayErrorClass,
) {
    let should_replace = current
        .map(|class| {
            dlq_replay_error_class_priority(next) > dlq_replay_error_class_priority(class)
                // This is intentionally one-way: promote generic crypto to
                // the actionable config-unavailable subtype, but never let a
                // later generic crypto failure erase that machine-readable
                // recovery predicate from retained DLQ aggregates.
                || matches!(
                    (class, next),
                    (
                        DlqReplayErrorClass::Crypto,
                        DlqReplayErrorClass::CryptoConfigUnavailable { .. }
                    )
                )
                || matches!(
                    (class, next),
                    (
                        DlqReplayErrorClass::CryptoConfigUnavailable {
                            version: Some(current_version)
                        },
                        DlqReplayErrorClass::CryptoConfigUnavailable {
                            version: Some(next_version)
                        }
                    ) if current_version != next_version
                )
        })
        .unwrap_or(true);
    if should_replace {
        *current = match (*current, next) {
            (
                Some(DlqReplayErrorClass::CryptoConfigUnavailable {
                    version: Some(current_version),
                }),
                DlqReplayErrorClass::CryptoConfigUnavailable {
                    version: Some(next_version),
                },
            ) if current_version != next_version => {
                Some(DlqReplayErrorClass::CryptoConfigUnavailable { version: None })
            }
            _ => Some(next),
        };
    }
}

fn aggregate_dlq_replay_error_class(
    replay: Option<DlqReplayErrorClass>,
    retained: Option<DlqReplayErrorClass>,
) -> DlqReplayErrorClass {
    // Retained records are only those preserved by
    // `is_temporarily_undecodable_dlq_error`; today that means encrypted DLQ
    // lines whose config/key material is temporarily unavailable, which always
    // classifies as Crypto. If a future retained class is added, revisit the
    // active-vs-retained precedence rules instead of silently inheriting the
    // current active-failure preference.
    debug_assert!(
        retained.is_none()
            || matches!(
                retained,
                Some(
                    DlqReplayErrorClass::Crypto
                        | DlqReplayErrorClass::CryptoConfigUnavailable { .. }
                )
            ),
        "new retained DLQ replay class requires an explicit aggregate precedence decision"
    );
    let mut aggregate = replay.or(retained);
    if replay == Some(DlqReplayErrorClass::LegacyRefused) {
        if let Some(retained) = retained {
            merge_dlq_replay_error_class(&mut aggregate, retained);
        }
    }
    aggregate.unwrap_or(DlqReplayErrorClass::Dispatch)
}

fn dlq_replay_aggregate_error(class: DlqReplayErrorClass, detail: String) -> MatrixError {
    match class {
        DlqReplayErrorClass::Dispatch => dlq_dispatch_failed(detail),
        DlqReplayErrorClass::SessionHistory => MatrixError::SessionHistoryCorrupt(detail),
        DlqReplayErrorClass::Serialization => dlq_serialization_failed(detail),
        DlqReplayErrorClass::CryptoConfigUnavailable { version } => {
            dlq_crypto_config_unavailable_with_context(version, detail)
        }
        DlqReplayErrorClass::Crypto => dlq_crypto_failed(detail),
        DlqReplayErrorClass::CapSaturation => dlq_cap_saturation(detail),
        DlqReplayErrorClass::Io => dlq_io_failed(detail),
        DlqReplayErrorClass::LegacyRefused => legacy_dlq_envelope_refused(detail),
    }
}

fn dlq_rekey_decode_error(err: MatrixError, state_dir: &Path) -> MatrixError {
    match err {
        MatrixError::LegacyDlqEnvelopeRefused(_)
        | MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable { .. }) => err,
        err => dlq_rekey_decode_error_with_context(err, state_dir),
    }
}

fn dlq_rekey_decode_error_with_context(err: MatrixError, state_dir: &Path) -> MatrixError {
    let detail = format!(
        "rekey: failed to decode DLQ line under OLD passphrase ({err}); \
         resolve corrupt records manually (move to {} or drop) \
         and retry the rekey",
        matrix_inbound_dlq_quarantine_path(state_dir).display()
    );
    match err {
        MatrixError::DlqSerialization(_) => dlq_serialization_failed(detail),
        MatrixError::DlqIo(_) => dlq_io_failed(detail),
        MatrixError::DlqCapSaturation(_) => dlq_cap_saturation(detail),
        MatrixError::DlqCrypto(_) | MatrixError::MissingStoreSecret => dlq_crypto_failed(detail),
        _ => {
            debug_assert!(
                false,
                "non-DLQ MatrixError reached DLQ rekey decode classifier: {}",
                err.kind()
            );
            tracing::error!(
                kind = err.kind(),
                "non-DLQ MatrixError reached DLQ rekey decode classifier; \
                 preserving historical crypto fallback"
            );
            dlq_crypto_failed(detail)
        }
    }
}

pub(super) fn is_temporarily_undecodable_dlq_error(err: &MatrixError) -> bool {
    match err {
        // SECURITY: `LegacyDlqEnvelopeRefused` was previously classified
        // here, but its semantics differ from `MissingStoreSecret`. The
        // latter is genuinely recoverable: an operator who flips
        // matrix.encrypted=true→false→true gets the records back.
        // `LegacyDlqEnvelopeRefused` is the operator's EXPLICIT policy
        // — there's no toggle that makes the records decodable. The
        // prior classification routed refused-legacy records into the
        // "preserved last in live DLQ" tail-truncation class, which
        // means cap-pressure (concurrent inbound flood + dispatch
        // retries) silently dropped them via FIFO truncation rather
        // than preserving the operator-attended forensic record. They
        // now classify as `Corrupt` and route to quarantine — same
        // outcome the operator would get for any other refused
        // record class.
        MatrixError::MissingStoreSecret => true,
        MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable { .. }) => true,
        _ => false,
    }
}

/// Stream the inbound DLQ file line-by-line into a `Vec<String>`,
/// returning `None` if the file is absent. Used by `replay_matrix_inbound_dlq`
/// phases 1 and 3.
///
/// SECURITY: the pre-fix code path used `tokio::fs::read_to_string`
/// which materializes the entire file into a single String before the
/// `.lines()` split — under a sustained downstream dispatch outage a
/// 10K-record DLQ with ~88 KiB per encrypted record (worst case
/// `MATRIX_INBOUND_BODY_MAX_BYTES` + envelope overhead) gives a
/// ~900 MiB transient String buffer ALONGSIDE the ~900 MiB
/// `Vec<String>` it gets split into. Streaming reads one line at a
/// time and pushes directly into the Vec, removing the duplicate
/// allocation — the in-RAM peak drops by ~half. The total Vec
/// footprint is still bounded by `MATRIX_INBOUND_DLQ_MAX_RECORDS` ×
/// per-record size, but the duplicate-buffer-during-read window is
/// gone. Mirrors the streaming pattern already in
/// `matrix_inbound_dlq_line_count`.
/// Per-line byte cap for the streaming DLQ reader. A single record
/// is at most ~88 KiB (`MATRIX_INBOUND_BODY_MAX_BYTES` + base64
/// inflation + envelope). 128 KiB gives generous headroom while
/// bounding the worst-case single-line allocation if a same-uid
/// attacker plants a regular file with a multi-GiB unbroken
/// `[no-newline]` blob at `inbound-dlq.jsonl`.
pub(super) const MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES: usize = 128 * 1024;

/// Total-line cap for the streaming DLQ reader. The write path
/// already enforces `MATRIX_INBOUND_DLQ_MAX_RECORDS`, but a
/// planted regular file could carry far more lines. The safety
/// margin of 1024 absorbs concurrent appends that arrived during
/// replay phase 1 (those land in `new_lines` and merge in phase
/// 3, so the read here may legitimately observe a slightly larger
/// file than the live append boundary).
const MATRIX_INBOUND_DLQ_REPLAY_LINE_COUNT_MAX: usize = MATRIX_INBOUND_DLQ_MAX_RECORDS + 1024;

pub(super) async fn read_matrix_inbound_dlq_lines_streaming(
    path: &Path,
) -> Result<Option<Vec<String>>, MatrixError> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    // O_NOFOLLOW so a same-uid attacker who can plant a symlink at
    // `inbound-dlq.jsonl` cannot redirect the replay reader to an
    // attacker-chosen file. See `matrix_inbound_dlq_line_count` for
    // the threat-model commentary.
    let file = match open_matrix_dlq_for_read_no_follow(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(dlq_io_failed(format!(
                "read Matrix inbound DLQ {}: {err}",
                path.display()
            )))
        }
    };
    let mut reader = tokio::io::BufReader::new(file);
    let mut out: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    // Per-line cap: a single legitimate record encodes to ≤88 KiB;
    // 128 KiB is generous. A planted oversize unbroken byte stream
    // fails closed before we accumulate it into a String.
    let line_cap = MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES + 1; // +1 for newline
    loop {
        buf.clear();
        let bytes_read = (&mut reader)
            .take(line_cap as u64)
            .read_until(b'\n', &mut buf)
            .await
            .map_err(|err| {
                dlq_io_failed(format!("read Matrix inbound DLQ {}: {err}", path.display()))
            })?;
        if bytes_read == 0 {
            break;
        }
        // Fail closed if the cap was hit without a terminating newline.
        if bytes_read >= line_cap && buf.last().copied() != Some(b'\n') {
            return Err(dlq_cap_saturation(format!(
                "Matrix inbound DLQ {} contains a line exceeding {} bytes; refusing to load",
                path.display(),
                MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES
            )));
        }
        if buf.last().copied() == Some(b'\n') {
            buf.pop();
        }
        if buf.last().copied() == Some(b'\r') {
            buf.pop();
        }
        let trimmed = std::str::from_utf8(&buf)
            .map_err(|err| {
                dlq_serialization_failed(format!(
                    "Matrix inbound DLQ {} contains non-UTF-8 line: {err}",
                    path.display()
                ))
            })?
            .trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
            if out.len() > MATRIX_INBOUND_DLQ_REPLAY_LINE_COUNT_MAX {
                return Err(dlq_cap_saturation(format!(
                    "Matrix inbound DLQ {} exceeds {} line cap; refusing to load (planted file?)",
                    path.display(),
                    MATRIX_INBOUND_DLQ_REPLAY_LINE_COUNT_MAX
                )));
            }
        }
    }
    Ok(Some(out))
}

pub(super) async fn replay_matrix_inbound_dlq(
    state_dir: &Path,
    config: &MatrixConfig,
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError> {
    replay_matrix_inbound_dlq_with_dispatcher(
        state_dir,
        config,
        ws_state,
        state,
        &ProductionMatrixDlqDispatcher,
    )
    .await
}

// Internal test seam: production dispatch still delegates to
// dispatch_matrix_dlq_record, while tests can record or fail dispatches without
// taking ownership of the replay loop's state-reset behavior.
#[async_trait::async_trait]
pub(super) trait MatrixDlqDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        ws_state: Arc<WsServerState>,
        state: Arc<RwLock<MatrixRuntimeState>>,
        state_dir: &Path,
        config: &MatrixConfig,
        record: &MatrixInboundDlqRecord,
    ) -> Result<(), MatrixError>;
}

struct ProductionMatrixDlqDispatcher;

#[async_trait::async_trait]
impl MatrixDlqDispatcher for ProductionMatrixDlqDispatcher {
    async fn dispatch(
        &self,
        ws_state: Arc<WsServerState>,
        state: Arc<RwLock<MatrixRuntimeState>>,
        state_dir: &Path,
        config: &MatrixConfig,
        record: &MatrixInboundDlqRecord,
    ) -> Result<(), MatrixError> {
        dispatch_matrix_dlq_record(ws_state, state, state_dir, config, record).await
    }
}

pub(super) async fn replay_matrix_inbound_dlq_with_dispatcher<D>(
    state_dir: &Path,
    config: &MatrixConfig,
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    dispatcher: &D,
) -> Result<(), MatrixError>
where
    D: MatrixDlqDispatcher,
{
    let path = matrix_inbound_dlq_path(state_dir);
    let lock = state.read().dlq_io_lock();

    // Phase 1: snapshot the current DLQ contents under the lock and
    // release it. Holding the lock across dispatch (a per-record
    // agent-pipeline call that can block on the LLM) would block every
    // inbound `append_matrix_inbound_dlq` call for as long as replay
    // takes — a single slow LLM round-trip on one DLQ record means new
    // dispatch failures get blocked at the lock, not the cap, dropping
    // them silently on shutdown. We track the original line set so
    // phase 3 can preserve any new appends that arrived during dispatch.
    // SECURITY: stream the DLQ file via BufReader (see
    // `read_matrix_inbound_dlq_lines_streaming` security note) rather
    // than `read_to_string` to avoid a ~900 MiB transient String
    // alongside the same-size `Vec<String>` under a saturated DLQ.
    let original_lines = {
        let _guard = lock.lock().await;
        match read_matrix_inbound_dlq_lines_streaming(&path).await? {
            Some(lines) => lines,
            None => {
                state.write().clear_inbound_dlq_durability_error();
                return Ok(());
            }
        }
    };
    // Multiset rather than HashSet so byte-identical lines (e.g., the
    // same Matrix event ID delivered twice in a redelivery storm) are
    // tracked with their multiplicity. A plain HashSet would let two
    // concurrent appends of the same encoded record collapse to one,
    // and the phase-3 diff would silently drop the second concurrent
    // append after the first dispatched.
    let mut original_multiset: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for line in &original_lines {
        *original_multiset.entry(line.clone()).or_insert(0) += 1;
    }

    // Daemon-lifetime DLQ key cache. v2 (Argon2id, current write
    // format) and v1 (HKDF, legacy read-only) each derive at most
    // once per daemon process. Pre-derivation runs ONLY when the
    // config is encrypted-mode — plaintext mode has no passphrase
    // resolvable, so `ensure_v*` would fail with `MissingStoreSecret`
    // and abort the entire replay phase. An adversary-reachable DoS
    // followed: a peer-controlled message body containing the
    // literal substring `"version":2` lands in a plaintext DLQ; on
    // every subsequent replay tick a substring scan would force
    // `ensure_v2` and wedge the channel in Error indefinitely.
    //
    // The toggle-back-from-encrypted recovery still works through
    // a different path: per-record decode introspects line shape
    // (NOT `config.encrypted()`), and the inner decode at
    // `decode_matrix_inbound_dlq_record_inner` returns typed
    // `DlqCryptoFailure::ConfigUnavailable`
    // when an encrypted-shape line arrives without a cached key.
    // The replay loop classifies that error as temporarily undecodable
    // and keeps the line live for a later toggle-back replay; plaintext
    // records continue to drain.
    // Operators who toggled true→false and want their encrypted
    // records back must toggle to true first (per the typed error
    // message and the `docs/channels.md` rekey-lifecycle section).
    let dlq_keys = state.read().dlq_keys();
    if config.encrypted() {
        // Pre-derive v2 unconditionally because phase-3 re-encode
        // ALWAYS emits v2. v1 derivation is on-demand: only fires
        // when a v1 envelope is actually on disk (cheap HKDF; ~µs).
        dlq_keys.ensure_v2(state_dir, config)?;
        let needs_v1 = original_lines
            .iter()
            .any(|line| line.contains("\"version\":1"));
        if needs_v1 {
            dlq_keys.ensure_v1(state_dir, config)?;
        }
    }

    // Phase 2: classify and dispatch each record OUTSIDE the lock.
    // Concurrent inbound failures land in the live file via
    // `append_matrix_inbound_dlq`; we'll merge them in during phase 3.
    let mut remaining_records: Vec<MatrixInboundDlqRecord> = Vec::new();
    let mut corrupt_lines: Vec<String> = Vec::new();
    // Lines that are well-formed but cannot be decoded under the
    // current config (e.g., encrypted-shape lines under
    // matrix.encrypted=false). Preserved in the live DLQ rather
    // than quarantined so a config restore drains them naturally.
    let mut preserved_temporarily_undecodable: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut legacy_v1_reencoded_count = 0usize;
    let mut legacy_v1_drained_count = 0usize;
    let mut legacy_v1_quarantined_count = 0usize;
    // Per-tick log-volume caps. A full DLQ (10K records) under a
    // sustained downstream outage would otherwise emit 10K warn lines
    // per replay sync tick — pure log volume amplification of the
    // already-aggregated `errors` Vec which surfaces the same info
    // via the typed aggregate return path. Log the first N per kind, then
    // summarize the suppressed count once at the end of the loop.
    const MATRIX_DLQ_REPLAY_PER_KIND_WARN_CAP: usize = 10;
    let mut replay_error_class: Option<DlqReplayErrorClass> = None;
    let mut retained_error_class: Option<DlqReplayErrorClass> = None;
    let mut dispatch_failure_warn_count = 0usize;
    let mut quarantine_warn_count = 0usize;
    let mut corrupt_warn_count = 0usize;
    let mut temporarily_undecodable_warn_count = 0usize;
    let mut suppressed_dispatch_failure_count = 0usize;
    let mut suppressed_quarantine_count = 0usize;
    let mut suppressed_corrupt_count = 0usize;
    let mut suppressed_temporarily_undecodable_count = 0usize;
    for line in original_lines.iter() {
        let legacy_envelope_version = matrix_inbound_dlq_envelope_version(line)
            .filter(|version| *version == MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY);
        let classified = match decode_matrix_inbound_dlq_record_with_policy(
            Path::new(""),
            None,
            line,
            Some(&dlq_keys),
            config.legacy_dlq_envelope_policy,
        ) {
            Ok(record) => DlqReplayLine::Decoded {
                record,
                legacy_envelope_version,
            },
            Err(err) => {
                let error_class = classify_dlq_replay_error(&err);
                // Distinguish "permanently undecodable" (corrupt
                // ciphertext, malformed JSON shape, unknown envelope
                // version) from "temporarily undecodable" (operator
                // toggled matrix.encrypted=true → false with v1/v2
                // records still on disk). The MissingStoreSecret
                // case is recoverable: if the operator flips
                // matrix.encrypted back to true, the records decode
                // again. Quarantining them as corrupt would lose
                // that recovery path. Keep them in the live DLQ as
                // `TemporarilyUndecodable` and let the operator
                // surface them via the durability counters; a
                // subsequent replay tick under matrix.encrypted=true
                // drains naturally.
                if is_temporarily_undecodable_dlq_error(&err) {
                    DlqReplayLine::TemporarilyUndecodable {
                        raw: line.clone(),
                        error: err.to_string(),
                        error_class,
                    }
                } else {
                    DlqReplayLine::Corrupt {
                        raw: line.clone(),
                        error: err.to_string(),
                        error_class,
                    }
                }
            }
        };
        match classified {
            DlqReplayLine::Decoded {
                record,
                legacy_envelope_version,
            } => {
                match dispatcher
                    .dispatch(ws_state.clone(), state.clone(), state_dir, config, &record)
                    .await
                {
                    Ok(()) => {
                        if legacy_envelope_version.is_some() {
                            legacy_v1_drained_count += 1;
                        }
                        state.write().reset_inbound_failures();
                    }
                    Err(err @ MatrixError::SessionHistoryCorrupt(_)) => {
                        merge_dlq_replay_error_class(
                            &mut replay_error_class,
                            classify_dlq_replay_error(&err),
                        );
                        if legacy_envelope_version.is_some() {
                            legacy_v1_quarantined_count += 1;
                        }
                        let event_id_log = sanitize_homeserver_identifier(record.event_id.as_str());
                        if quarantine_warn_count < MATRIX_DLQ_REPLAY_PER_KIND_WARN_CAP {
                            quarantine_warn_count += 1;
                            warn!(
                                event_id = %event_id_log,
                                error = %err,
                                "Matrix DLQ replay encountered permanent session-history corruption; moving record to quarantine"
                            );
                        } else {
                            suppressed_quarantine_count += 1;
                        }
                        errors.push(format!(
                            "event {}: session-history corruption (quarantined): {err}",
                            event_id_log
                        ));
                        corrupt_lines.push(line.clone());
                    }
                    Err(err) => {
                        merge_dlq_replay_error_class(
                            &mut replay_error_class,
                            classify_dlq_replay_error(&err),
                        );
                        if legacy_envelope_version.is_some() {
                            legacy_v1_reencoded_count += 1;
                        }
                        // Log per-record dispatch failures at warn so
                        // the trace is queryable per event_id. The
                        // aggregate error returned later only carries
                        // the first 3 of N, hiding the long tail.
                        let event_id_log = sanitize_homeserver_identifier(record.event_id.as_str());
                        if dispatch_failure_warn_count < MATRIX_DLQ_REPLAY_PER_KIND_WARN_CAP {
                            dispatch_failure_warn_count += 1;
                            warn!(
                                event_id = %event_id_log,
                                error = %err,
                                "Matrix DLQ replay dispatch failed"
                            );
                        } else {
                            suppressed_dispatch_failure_count += 1;
                        }
                        errors.push(format!("event {}: {err}", event_id_log));
                        remaining_records.push(record);
                    }
                }
            }
            DlqReplayLine::Corrupt {
                raw,
                error,
                error_class,
            } => {
                merge_dlq_replay_error_class(&mut replay_error_class, error_class);
                if matrix_inbound_dlq_envelope_version(&raw)
                    == Some(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY)
                {
                    legacy_v1_quarantined_count += 1;
                }
                // Move undecodable lines to a sibling quarantine file
                // so the live DLQ can drain. Without this, every
                // replay tick re-classifies them as Corrupt, the
                // dlq_replay streak ticks up monotonically, and the
                // channel stays in Error forever — even after every
                // recoverable record has dispatched. The quarantine
                // file preserves the raw line for forensic recovery.
                if corrupt_warn_count < MATRIX_DLQ_REPLAY_PER_KIND_WARN_CAP {
                    corrupt_warn_count += 1;
                    warn!(
                        error = %error,
                        "Matrix DLQ replay encountered an undecodable line; moving to quarantine"
                    );
                } else {
                    suppressed_corrupt_count += 1;
                }
                errors.push(format!("undecodable line (quarantined): {error}"));
                corrupt_lines.push(raw);
            }
            DlqReplayLine::TemporarilyUndecodable {
                raw,
                error,
                error_class,
            } => {
                merge_dlq_replay_error_class(&mut retained_error_class, error_class);
                // Keep in the live DLQ — flipping matrix.encrypted
                // back to true makes the records decode again. We
                // surface a warn so the operator sees the signal
                // and append the line to remaining_records so it
                // gets preserved across the rewrite.
                //
                // This is the most likely flood path because a single
                // operator config toggle (`matrix.encrypted=true` →
                // `false` with v1/v2 records still on disk) routes
                // EVERY existing record through here on EVERY replay
                // tick. Without the cap a 10K-record DLQ produces 10K
                // warns per tick — the same flood the dispatch-failure
                // cap above was added to prevent.
                if temporarily_undecodable_warn_count < MATRIX_DLQ_REPLAY_PER_KIND_WARN_CAP {
                    temporarily_undecodable_warn_count += 1;
                    warn!(
                        error = %error,
                        "Matrix DLQ replay encountered a temporarily-undecodable line \
                         (likely matrix.encrypted=false with v1/v2 records on disk); \
                         preserving in the live DLQ for recovery on config restore"
                    );
                } else {
                    suppressed_temporarily_undecodable_count += 1;
                }
                errors.push(format!("temporarily undecodable: {error}"));
                preserved_temporarily_undecodable.push(raw);
            }
        }
    }

    // Per-tick suppressed-warn summary. Closes out the log-volume
    // cap applied to dispatch-failure and quarantine warns inside
    // the loop. The aggregate counts hit `cara status` via the
    // `DlqDispatchFailure` return shape; this surfaces the suppressed counts
    // in the log channel so an operator paging through tracing can
    // see the long tail without flooding.
    if suppressed_dispatch_failure_count > 0 {
        warn!(
            suppressed = suppressed_dispatch_failure_count,
            logged = dispatch_failure_warn_count,
            "Matrix DLQ replay dispatch failures (suppressed remainder; channel status \
             `last_error` carries a first-3-of-N preview, full records remain on disk in \
             the live DLQ for the next replay tick)"
        );
    }
    if suppressed_quarantine_count > 0 {
        warn!(
            suppressed = suppressed_quarantine_count,
            logged = quarantine_warn_count,
            "Matrix DLQ replay quarantine events (suppressed remainder; channel status \
             `last_error` carries a first-3-of-N preview, full records remain in the \
             quarantine file at matrix/inbound_dlq.corrupt.jsonl)"
        );
    }
    if suppressed_corrupt_count > 0 {
        warn!(
            suppressed = suppressed_corrupt_count,
            logged = corrupt_warn_count,
            "Matrix DLQ replay undecodable lines (suppressed remainder; corrupt lines were \
             moved to the quarantine file regardless of log suppression)"
        );
    }
    if suppressed_temporarily_undecodable_count > 0 {
        warn!(
            suppressed = suppressed_temporarily_undecodable_count,
            logged = temporarily_undecodable_warn_count,
            "Matrix DLQ replay temporarily-undecodable lines (suppressed remainder; lines \
             preserved in the live DLQ — typical cause: matrix.encrypted=false with v1/v2 \
             records on disk, flip back to true to decode)"
        );
    }

    // Append corrupt lines to the quarantine file (best-effort).
    // Quarantine writes go to a sibling file that no other DLQ path
    // touches, so they don't need the dlq_io_lock.
    let quarantine_failed_err = if corrupt_lines.is_empty() {
        None
    } else {
        match append_matrix_inbound_dlq_quarantine(state_dir, &corrupt_lines).await {
            Ok(()) => None,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to write Matrix DLQ quarantine file; corrupt lines remain in live DLQ \
                     — channel will stay in Error until the operator unblocks the quarantine path"
                );
                Some(err)
            }
        }
    };

    // Phase 3: re-acquire the lock briefly to merge any concurrently-
    // appended records back into the live DLQ along with dispatch
    // failures (and corrupt lines if quarantine failed).
    //
    // Helper: log the in-memory remaining_records' event_ids before
    // propagating an error so an operator chasing a "where did my
    // events go?" report has a forensic recovery list. Phase-3 failure
    // means those records will not be persisted back to disk. Also
    // mirror the IDs into channel-status so the recovery list survives
    // a journal rotation between the failure and the operator's page.
    let lost_persist_state = state.clone();
    let log_lost_remaining = |where_label: &str, err: &dyn std::fmt::Display| {
        if !remaining_records.is_empty() {
            let lost_ids: Vec<String> = remaining_records
                .iter()
                .map(|r| sanitize_homeserver_identifier(r.event_id.as_str()))
                .collect();
            // JSON-encoded so log aggregators can parse the IDs out as
            // an array; see the cap-clamp branch below for the same
            // discipline.
            let lost_event_ids_json =
                serde_json::to_string(&lost_ids).expect("Vec<&str> always serializes to JSON");
            tracing::error!(
                stage = where_label,
                error = %err,
                lost_event_ids = %lost_event_ids_json,
                path = %path.display(),
                "Matrix DLQ phase-3 cleanup failed; dispatch-failed records held in memory \
                 cannot be persisted back to disk and may be lost on shutdown. Operator \
                 may need to manually replay events from session log."
            );
            // Stamp a durability error and the lost-IDs together so a
            // first-time phase-3 failure on a fresh daemon immediately
            // pins the channel into Error via the durability-error
            // path — symmetrical with the cap-clamp branch below,
            // which is the only other path that surfaces lost
            // event_ids without a prior dlq_replay streak.
            let lost_count = remaining_records.len();
            let mut guard = lost_persist_state.write();
            guard.record_inbound_dlq_append_failure(format!(
                "Matrix inbound DLQ phase-3 cleanup ({where_label}) failed; \
                 {lost_count} dispatch-failed record(s) held in memory cannot be \
                 persisted back to disk: {err}"
            ));
            guard.record_inbound_dlq_lost_event_ids(
                remaining_records
                    .iter()
                    .map(|r| sanitize_homeserver_identifier(r.event_id.as_str())),
            );
        }
    };

    {
        let _guard = lock.lock().await;
        // Stream the re-read same as phase 1 so the duplicate
        // String-then-Vec allocation window is gone here too.
        let new_lines = match read_matrix_inbound_dlq_lines_streaming(&path).await {
            Ok(Some(lines)) => {
                let mut snapshot_remaining = original_multiset.clone();
                let mut new_lines = Vec::new();
                for line in lines {
                    match snapshot_remaining.get_mut(&line) {
                        Some(count) if *count > 0 => {
                            // This line was already in phase-1 snapshot;
                            // accounted for. Decrement multiplicity.
                            *count -= 1;
                        }
                        _ => {
                            // Concurrent append since phase 1 — preserve.
                            new_lines.push(line);
                        }
                    }
                }
                new_lines
            }
            Ok(None) => Vec::new(),
            Err(err) => {
                // `read_matrix_inbound_dlq_lines_streaming` already
                // wraps the underlying io::Error with the path; log
                // the typed error via Display and propagate.
                log_lost_remaining("re-read", &err);
                return Err(err);
            }
        };

        // Final live-file content: new appends since phase 1, then
        // dispatch failures, then corrupt lines (only if quarantine
        // failed — successful quarantine moves them to the sibling).
        let preserved_corrupt: &[String] = if quarantine_failed_err.is_some() {
            &corrupt_lines
        } else {
            &[]
        };
        let mut merged_lines =
            Vec::with_capacity(new_lines.len() + remaining_records.len() + preserved_corrupt.len());
        // Order matters for the cap-clamp below: dispatch-failed records
        // (`remaining_records`) come FIRST because they have already
        // earned their slot — they survived classification and dispatch
        // in phase 2 and are awaiting retry. Concurrent new appends
        // (`new_lines`) come second; under cap pressure these are the
        // safer drop target since the next replay tick will re-process
        // any new appends written after this rewrite. `truncate` keeps
        // the prefix and drops from the tail, so this ordering yields
        // FIFO eviction (oldest-survives) under load — the correct
        // policy when an adversary-controlled inbound burst races a
        // legitimate dispatch backlog. Track encode failures so we
        // detect the all-fail-edge below.
        let mut encode_failure_count = 0usize;
        let mut encode_failed_event_ids: Vec<String> = Vec::new();
        for record in &remaining_records {
            // Reuse the per-replay v2 (Argon2id) AEAD key derived
            // above — re-deriving Argon2id for each remaining
            // record under `dlq_io_lock` is wasted work that throttles
            // concurrent `append_matrix_inbound_dlq` calls. The
            // re-encode always emits v2 regardless of the record's
            // original on-disk version (v1 records get rewritten as
            // v2 if dispatch failed, completing the v1→v2 rotation
            // on the next replay tick).
            match encode_matrix_inbound_dlq_record_with_key(dlq_keys.v2(), record) {
                Ok(line) => merged_lines.push(line),
                Err(err) => {
                    encode_failure_count += 1;
                    let event_id_log = sanitize_homeserver_identifier(record.event_id.as_str());
                    // SECURITY: push the SANITIZED form, never the raw
                    // peer-controlled event_id. `inbound_dlq_lost_event_ids`
                    // surfaces through `/control/channels` to the
                    // operator UI / `cara status`, so a hostile
                    // homeserver could otherwise embed ANSI escapes,
                    // bidi overrides, or zero-width chars to spoof a
                    // SAS prompt or rearrange forensic IDs on the
                    // operator's terminal. Every sibling site that
                    // feeds record_inbound_dlq_lost_event_ids already
                    // sanitizes (matrix.rs:6976, 7008, 7867); a
                    // missed sanitization here was the regression
                    // introduced by 5ae35924.
                    encode_failed_event_ids.push(event_id_log.clone());
                    tracing::error!(
                        event_id = %event_id_log,
                        error = %err,
                        "Matrix DLQ replay phase-3 re-encode failed; record dropped from \
                         live DLQ. Operator may need to manually replay this event from \
                         session log."
                    );
                }
            }
        }
        // Surface a sticky durability error on ANY encode failure, not
        // only when all encodes fail. The pre-fix `encode_failure_count
        // == remaining_records.len()` guard meant a 9-of-10 partial
        // failure silently dropped the 10th record from disk with only
        // a tracing::error! signal (lost on log rotation / buffer
        // flush) — exactly the silent-DLQ-loss the durability-error
        // surface exists to prevent. Also record the lost event IDs
        // so the operator can correlate against session logs without
        // having to grep tracing output. Cap the recorded event-id
        // count to avoid unbounded `last_inbound_dlq_lost_event_ids`
        // growth under pathological corruption.
        if encode_failure_count > 0 {
            let total = remaining_records.len();
            let succeeded = total - encode_failure_count;
            state.write().record_inbound_dlq_append_failure(format!(
                "Matrix inbound DLQ replay phase-3 re-encoded {succeeded} of {total} \
                 dispatch-failed records; {encode_failure_count} permanently dropped from \
                 disk (check store key + HKDF info constants, then replay from session log)"
            ));
            state
                .write()
                .record_inbound_dlq_lost_event_ids(encode_failed_event_ids);
        }
        // Order under quarantine failure: preserved_corrupt (which
        // includes refused-legacy records under
        // `legacyEnvelopePolicy=refuse`) is the operator's ONLY
        // forensic copy when the sibling quarantine append fails —
        // those records are NOT retryable (refuse-policy is an
        // explicit operator decision) and they will not return via
        // a future replay tick. Hoist them above `new_lines` under
        // quarantine failure so cap-clamp drops re-processable new
        // appends (which the next tick will see) before forensic-
        // attention-required corrupt lines. Without this, a high-
        // inbound-rate channel concurrent with a quarantine I/O
        // outage silently loses the refused-legacy record AND the
        // operator's only signal that the refuse-policy was hit.
        if quarantine_failed_err.is_some() {
            merged_lines.extend(preserved_corrupt.iter().cloned());
            merged_lines.extend(new_lines);
        } else {
            merged_lines.extend(new_lines);
            // preserved_corrupt is empty when quarantine succeeded.
        }
        // Temporarily-undecodable lines (e.g., encrypted records on
        // disk while matrix.encrypted=false) are kept in the live
        // DLQ verbatim so a future config restore can drain them.
        // They join last so the cap-clamp drops them first under
        // contention.
        merged_lines.extend(preserved_temporarily_undecodable.iter().cloned());

        // Cap-clamp the rewrite. The standard `append_matrix_inbound_dlq`
        // path enforces MATRIX_INBOUND_DLQ_MAX_RECORDS but this rewrite
        // bypasses that path; without a clamp, an adversary-controlled
        // inbound rate during phase 2 (concurrent new failures) plus
        // dispatch-failed remaining_records can push the merged file past
        // the cap.
        if merged_lines.len() > MATRIX_INBOUND_DLQ_MAX_RECORDS {
            let dropped = merged_lines.len() - MATRIX_INBOUND_DLQ_MAX_RECORDS;
            // Decode the tail slice we're about to truncate so the
            // dropped event IDs land in `cara status` and the journal,
            // not just the count. Without this, operators get
            // "47 records dropped to fit" with no way to know which
            // Matrix events vanished — they can't ask correspondents
            // to resend or audit lost conversations. Decode failures
            // are tolerable (the line was still going to drop) but we
            // log them for forensic completeness.
            let (dropped_ids, decode_failures) = collect_dropped_event_ids_from_tail(
                &merged_lines[MATRIX_INBOUND_DLQ_MAX_RECORDS..],
                Some(&dlq_keys),
            );
            // Encode the dropped event_ids as a JSON array string so log
            // aggregators (Loki/ELK/Datadog) can parse them as a list.
            // `?dropped_ids` would emit Rust Debug format (e.g.
            // `["a", "b"]` with quoting/spacing not guaranteed to be
            // valid JSON), which forces aggregators to either string-
            // match or fall back to per-line regex extraction.
            let dropped_event_ids_json =
                serde_json::to_string(&dropped_ids).expect("Vec<String> always serializes to JSON");
            warn!(
                kept = MATRIX_INBOUND_DLQ_MAX_RECORDS,
                dropped = dropped,
                dropped_event_ids = %dropped_event_ids_json,
                decode_failures = decode_failures,
                "Matrix DLQ replay merge exceeded record cap; truncating to FIFO oldest \
                 (dropping {dropped} most-recent appends to retain dispatch-failed retries)"
            );
            // A WAVE of decode failures (vs a single corrupt record)
            // is a qualitatively different signal — almost always a
            // store-key mismatch from a previous daemon's
            // CARAPACE_CONFIG_PASSWORD or rekey-store rotation.
            // Surface it separately so the operator's investigation
            // path is "check key rotation history", not "ask peers
            // to resend events". Empty `dropped_ids` with a non-zero
            // decode_failures is the giveaway of this case.
            if decode_failures > 0 {
                warn!(
                    decode_failures,
                    dropped,
                    "Matrix DLQ tail-truncation could not decode {decode_failures} of \
                     {dropped} dropped records — likely store-key mismatch from a \
                     prior daemon's CARAPACE_CONFIG_PASSWORD or rekey-store rotation. \
                     Event IDs cannot be recovered for these records; investigate the \
                     key rotation history before assuming events were never received."
                );
            }
            merged_lines.truncate(MATRIX_INBOUND_DLQ_MAX_RECORDS);
            {
                let mut guard = state.write();
                guard.record_inbound_dlq_append_failure(format!(
                    "Matrix inbound DLQ replay merge exceeded {MATRIX_INBOUND_DLQ_MAX_RECORDS}-record cap; \
                     {dropped} records dropped to fit{}",
                    if decode_failures > 0 {
                        format!(" ({decode_failures} unrecoverable due to key mismatch)")
                    } else {
                        String::new()
                    }
                ));
                if !dropped_ids.is_empty() {
                    guard.record_inbound_dlq_lost_event_ids(dropped_ids);
                }
                // Surface the undecodable-but-lost count as a numeric
                // metadata field so an operator running `cara status`
                // (or alerting on `extra.inboundDlqUndecodableLostCount`)
                // sees a signal even when individual IDs cannot be
                // recovered. Without this the only signal lives inside
                // the durability-error free-form string, which is
                // harder to threshold against.
                if decode_failures > 0 {
                    guard.status.inbound_dlq_undecodable_lost_count = guard
                        .status
                        .inbound_dlq_undecodable_lost_count
                        .saturating_add(decode_failures as u64);
                }
            }
        }

        // Emit the legacy-envelope-migration audit BEFORE the disk
        // commit (remove_file or replace_matrix_inbound_dlq_lines).
        // `record_matrix_inbound_dlq_legacy_envelope_processed` uses
        // `audit_blocking_or_enqueue_for_state_dir` and FAILS-CLOSED on
        // audit-dropped — so a saturated audit channel turns into an
        // Err return before any disk state changes. If we emitted
        // AFTER the commit (the pre-fix order), an audit drop would
        // leave the v1→v2 migration committed on disk with no
        // forensic record; the next replay tick would see only v2
        // records, emit no audit (record_count == 0 early return),
        // and the migration evidence would be PERMANENTLY lost.
        // Emitting before the commit can produce a duplicate audit
        // row if the disk commit then fails and the operator retries
        // (next replay tick re-finds the same v1 records and re-emits
        // the same migration event) — but a duplicate forensic record
        // is strictly better than a missing one. The legacy-envelope
        // audit emits the FULL counts including the quarantine path
        // because we know `quarantine_failed_err` and the quarantine
        // counts before getting here.
        let quarantine_count_for_audit = if quarantine_failed_err.is_some() {
            0
        } else {
            legacy_v1_quarantined_count
        };
        record_matrix_inbound_dlq_legacy_envelope_processed(
            state_dir,
            legacy_v1_reencoded_count,
            legacy_v1_drained_count,
            quarantine_count_for_audit,
        )?;

        if merged_lines.is_empty() {
            // Nothing left to retain: remove the file entirely so the
            // next replay tick early-returns at the NotFound branch.
            match tokio::fs::remove_file(&path).await {
                Ok(()) => sync_dlq_parent_dir_or_err(&path).await?,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    log_lost_remaining("remove", &err);
                    return Err(dlq_io_failed(format!(
                        "remove drained Matrix inbound DLQ {}: {err}",
                        path.display()
                    )));
                }
            }
            // Full drain → clear the at-cap latch unconditionally.
            state.write().inbound_dlq_at_cap_since_ms = None;
        } else {
            let merged_count = merged_lines.len();
            if let Err(err) = replace_matrix_inbound_dlq_lines(&path, merged_lines).await {
                log_lost_remaining("replace", &err);
                return Err(err);
            }
            // Stamp or clear the at-cap latch in lockstep with the
            // rewrite. Below cap → clear so the next append doesn't
            // short-circuit unnecessarily. At cap (cap-clamp truncated
            // exactly to MAX_RECORDS, or merged_count happened to land
            // exactly at the cap) → stamp now so the next appender's
            // pre-lock check short-circuits without paying a full file
            // read. Without this stamp the first post-rewrite append
            // pays one needless read_to_string to re-discover the cap
            // before stamping.
            {
                let mut guard = state.write();
                if merged_count < MATRIX_INBOUND_DLQ_MAX_RECORDS {
                    guard.inbound_dlq_at_cap_since_ms = None;
                } else {
                    guard.inbound_dlq_at_cap_since_ms = Some(now_millis());
                }
            }
        }

        if let Some(err) = quarantine_failed_err {
            // Audit already emitted above (with quarantine_count=0 for
            // the failed-quarantine branch). Just propagate the error.
            return Err(dlq_io_failed(format!(
                "Matrix DLQ replay quarantine failed: {err}"
            )));
        }
    }

    // (The post-rewrite audit emission that used to live here has
    // moved into the dlq_io_lock scope above so it runs BEFORE the
    // disk commit — `record_matrix_inbound_dlq_legacy_envelope_processed`
    // fails-closed on audit-drop, so emitting after the commit would
    // permanently lose the v1→v2 migration evidence on a saturated
    // audit channel. See the comment above the pre-rewrite emission
    // for the duplicate-row-vs-lost-row trade-off rationale.)

    if errors.is_empty() {
        // Full success: drop both the durability error AND the lost-
        // event-id list. A single transient phase-3 hiccup followed
        // by a clean replay should fully clear the operator-visible
        // surface, not pin stale IDs forever.
        let mut guard = state.write();
        guard.clear_inbound_dlq_durability_error();
        guard.clear_inbound_dlq_lost_event_ids();
        return Ok(());
    }
    let total_failures = errors.len();
    let summary = summarize_failures(&errors, 3);
    let detail = format!(
        "Matrix inbound DLQ replay still has {total_failures} undelivered or undecodable record(s); first 3: {summary}"
    );
    Err(dlq_replay_aggregate_error(
        // Active replay failures own the aggregate when present, except
        // legacy-policy refusal: that class is operator-actionable but must not
        // hide retained crypto/cap/IO evidence affecting other records.
        aggregate_dlq_replay_error_class(replay_error_class, retained_error_class),
        detail,
    ))
}

/// Outcome of `rotate_matrix_inbound_dlq_for_rekey`. The caller
/// cleans up `backup_path` after SQLite advance succeeds and
/// restores it (atomic rename) if SQLite advance fails.
#[derive(Debug)]
pub(crate) enum MatrixDlqRekeyOutcome {
    /// DLQ file does not exist or is empty — nothing to rotate.
    /// The caller proceeds with SQLite advance; no rollback needed.
    Skipped,
    /// DLQ contents successfully re-encrypted under the new key.
    /// `backup_path` is the OLD ciphertext stashed for rollback.
    /// On SQLite advance success, caller removes `backup_path`.
    /// On SQLite advance failure, caller renames `backup_path` →
    /// `inbound_dlq.jsonl` to restore the OLD ciphertext.
    Rotated {
        decoded_count: usize,
        backup_path: PathBuf,
    },
}

pub(super) fn reencode_matrix_inbound_dlq_lines_for_rekey(
    state_dir: &Path,
    original: &str,
    old_passphrase: &str,
    new_passphrase: &str,
    legacy_policy: MatrixLegacyDlqEnvelopePolicy,
) -> Result<Vec<String>, MatrixError> {
    let installation_id = read_or_create_installation_id(state_dir)?;
    let old_v1 = derive_matrix_inbound_dlq_key_v1_from(
        old_passphrase.as_bytes(),
        installation_id.as_bytes(),
    )?;
    let old_v2 = derive_matrix_inbound_dlq_key_v2_from(
        old_passphrase.as_bytes(),
        installation_id.as_bytes(),
    )?;
    let new_v2 = derive_matrix_inbound_dlq_key_v2_from(
        new_passphrase.as_bytes(),
        installation_id.as_bytes(),
    )?;
    let keys = MatrixDlqKeys::from_pre_derived(old_v1, old_v2);
    let mut decoded: Vec<MatrixInboundDlqRecord> = Vec::new();
    for line in original.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match decode_matrix_inbound_dlq_record_with_policy(
            Path::new(""),
            None,
            trimmed,
            Some(&keys),
            legacy_policy,
        ) {
            Ok(record) => {
                decoded.push(record);
                if decoded.len() > MATRIX_INBOUND_DLQ_MAX_RECORDS {
                    return Err(dlq_cap_saturation(format!(
                        "rekey: inbound DLQ has more than {} records; \
                         drain or manually split the DLQ before rotating the Matrix store",
                        MATRIX_INBOUND_DLQ_MAX_RECORDS
                    )));
                }
            }
            Err(err @ MatrixError::LegacyDlqEnvelopeRefused(_)) => {
                return Err(err);
            }
            Err(err) => {
                return Err(dlq_rekey_decode_error(err, state_dir));
            }
        }
    }
    decoded
        .iter()
        .map(|record| encode_matrix_inbound_dlq_record_with_key(Some(&new_v2), record))
        .collect()
}

/// Open the inbound-DLQ file (or rekey-backup file) for reading
/// with O_NOFOLLOW + file-type revalidation. Returns
/// `ErrorKind::NotFound` for the absent case so callers can short-
/// circuit; returns `ErrorKind::InvalidData` if the dirent we
/// opened is not a regular file (catches symlink / FIFO / socket /
/// device-node pre-plants). Used by the CLI rekey path which runs
/// in the daemon-down window between shutdown and the rekey.
#[cfg(unix)]
pub(super) fn open_matrix_inbound_dlq_no_follow_blocking(
    path: &Path,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    // O_NOFOLLOW + O_NONBLOCK: the post-open `is_fifo()` refusal
    // below only runs after `open` returns. Without O_NONBLOCK a
    // FIFO planted at the DLQ path blocks open(2) indefinitely
    // because the CLI rekey path has no outer timeout.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    let file_type = metadata.file_type();
    if !file_type.is_file()
        || file_type.is_symlink()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Matrix inbound DLQ rekey source is not a regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(super) fn open_matrix_inbound_dlq_no_follow_blocking(
    path: &Path,
) -> std::io::Result<std::fs::File> {
    // Pre-check via symlink_metadata when present to refuse symlinks
    // on non-Unix; encrypted Matrix state is refused on non-Unix per
    // `ensure_encrypted_matrix_state_supported_on_platform`, so the
    // residual race window is acceptable.
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Matrix inbound DLQ rekey source is a symlink, refusing to follow: {}",
                    path.display()
                ),
            ));
        }
    }

    // Path is operator-trusted: derived from `state_dir` config (set
    // by `matrix_inbound_dlq_path` / `matrix_inbound_dlq_rekey_backup_path`),
    // not user-supplied. Carapace is not an Actix app; the generic
    // Semgrep "Path Traversal with Actix" rule does not apply here.
    std::fs::File::open(path) // nosemgrep
}

pub(super) fn read_matrix_inbound_dlq_rekey_source(
    path: &Path,
    operation: &str,
) -> Result<Option<String>, MatrixError> {
    // SECURITY: O_NOFOLLOW + post-open file_type revalidation. The
    // CLI rekey path runs AFTER daemon shutdown but BEFORE the new
    // daemon starts (per the rekey-lock contract). Without
    // O_NOFOLLOW a same-uid attacker can swap
    // `state_dir/matrix/inbound.jsonl` for a symlink in that window;
    // the CLI would follow the symlink, decode redirected content
    // under the OLD passphrase, re-encrypt under the NEW, and write
    // back — best case a confusing decode failure, worst case
    // attacker-pre-encrypted content lands in the live DLQ under NEW
    // ciphertext where downstream dispatch trusts it as locally-
    // generated. Companion to the live-DLQ append/quarantine
    // O_NOFOLLOW hardening.
    let file = match open_matrix_inbound_dlq_no_follow_blocking(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(dlq_io_failed(format!(
                "{operation}: read inbound DLQ {}: {err}",
                path.display()
            )));
        }
    };
    // Bound per-line reads symmetrically with the live-DLQ replay/
    // count readers. `BufRead::read_line` would allocate the entire
    // next line into RAM before returning, so a planted regular file
    // passing the no-follow check but holding one huge newline-free
    // line would OOM during rekey. `.take(line_cap)` + `read_until`
    // caps each line at `MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES`,
    // and per-line UTF-8 validation runs before any push into
    // `content`. Mirrors `read_matrix_inbound_dlq_lines_streaming`.
    use std::io::Read as _;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    let mut non_empty_records = 0usize;
    let mut buf: Vec<u8> = Vec::new();
    let line_cap = MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES + 1; // +1 for newline
    loop {
        buf.clear();
        let bytes = (&mut reader)
            .take(line_cap as u64)
            .read_until(b'\n', &mut buf)
            .map_err(|err| {
                dlq_io_failed(format!(
                    "{operation}: read inbound DLQ {}: {err}",
                    path.display()
                ))
            })?;
        if bytes == 0 {
            break;
        }
        // Fail closed if the cap was hit without a terminating newline.
        if bytes >= line_cap && buf.last().copied() != Some(b'\n') {
            return Err(dlq_cap_saturation(format!(
                "{operation}: inbound DLQ {} contains a line exceeding {} bytes; refusing to load",
                path.display(),
                MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES
            )));
        }
        let line = std::str::from_utf8(&buf).map_err(|err| {
            dlq_serialization_failed(format!(
                "{operation}: inbound DLQ {} contains non-UTF-8 line: {err}",
                path.display()
            ))
        })?;
        if !line.trim().is_empty() {
            non_empty_records = non_empty_records.saturating_add(1);
            if non_empty_records > MATRIX_INBOUND_DLQ_MAX_RECORDS {
                return Err(dlq_cap_saturation(format!(
                    "{operation}: inbound DLQ has more than {} records; \
                     drain or manually split the DLQ before rotating the Matrix store",
                    MATRIX_INBOUND_DLQ_MAX_RECORDS
                )));
            }
        }
        content.push_str(line);
    }
    if content.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(content))
    }
}

pub(crate) fn restore_matrix_inbound_dlq_backup(
    backup_path: &Path,
    live_path: &Path,
) -> Result<(), MatrixError> {
    std::fs::rename(backup_path, live_path).map_err(|err| {
        dlq_io_failed(format!(
            "rekey: restore original DLQ {} → {}: {err}",
            backup_path.display(),
            live_path.display()
        ))
    })?;
    sync_dlq_parent_dir_or_err_blocking(live_path)?;
    Ok(())
}

pub(super) fn matrix_inbound_dlq_decodes_with_passphrase(
    state_dir: &Path,
    content: &str,
    passphrase: &str,
    legacy_policy: MatrixLegacyDlqEnvelopePolicy,
) -> Result<(), MatrixError> {
    let installation_id = read_or_create_installation_id(state_dir)?;
    let v1 =
        derive_matrix_inbound_dlq_key_v1_from(passphrase.as_bytes(), installation_id.as_bytes())?;
    let v2 =
        derive_matrix_inbound_dlq_key_v2_from(passphrase.as_bytes(), installation_id.as_bytes())?;
    let keys = MatrixDlqKeys::from_pre_derived(v1, v2);
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        decode_matrix_inbound_dlq_record_with_policy(
            Path::new(""),
            None,
            line,
            Some(&keys),
            legacy_policy,
        )?;
    }
    Ok(())
}

pub(crate) fn recover_matrix_inbound_dlq_rekey(
    state_dir: &Path,
    config: &MatrixConfig,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<MatrixDlqRekeyOutcome, MatrixError> {
    let legacy_policy = config.legacy_dlq_envelope_policy;
    let live_path = matrix_inbound_dlq_path(state_dir);
    let backup_path = matrix_inbound_dlq_rekey_backup_path(state_dir);
    let tmp_path = matrix_inbound_dlq_rekey_temp_path(state_dir);

    match std::fs::remove_file(&tmp_path) {
        Ok(()) => sync_dlq_parent_dir_or_err_blocking(&tmp_path)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(dlq_io_failed(format!(
                "rekey recovery: remove stale DLQ temp {}: {err}",
                tmp_path.display()
            )));
        }
    }

    let backup_exists = backup_path.exists();
    let live_content = read_matrix_inbound_dlq_rekey_source(&live_path, "rekey recovery")?;

    if backup_exists {
        if let Some(content) = live_content
            .as_deref()
            .filter(|content| !content.trim().is_empty())
        {
            if matrix_inbound_dlq_decodes_with_passphrase(
                state_dir,
                content,
                new_passphrase,
                legacy_policy,
            )
            .is_ok()
            {
                return Ok(MatrixDlqRekeyOutcome::Rotated {
                    decoded_count: content
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .count(),
                    backup_path,
                });
            }
            return Err(dlq_crypto_failed(format!(
                "rekey recovery: live DLQ {} exists but does not decode with the new passphrase while backup {} also exists; refusing to clobber possible NEW-keyed live data with OLD-keyed backup",
                live_path.display(),
                backup_path.display()
            )));
        }

        let Some(backup_content) =
            read_matrix_inbound_dlq_rekey_source(&backup_path, "rekey recovery")?
        else {
            return Ok(MatrixDlqRekeyOutcome::Rotated {
                decoded_count: 0,
                backup_path,
            });
        };
        let new_lines = reencode_matrix_inbound_dlq_lines_for_rekey(
            state_dir,
            &backup_content,
            old_passphrase,
            new_passphrase,
            legacy_policy,
        )?;
        replace_matrix_inbound_dlq_lines_blocking(&live_path, &new_lines)?;
        return Ok(MatrixDlqRekeyOutcome::Rotated {
            decoded_count: new_lines.len(),
            backup_path,
        });
    }

    match live_content {
        Some(content) if !content.trim().is_empty() => {
            let new_lines = reencode_matrix_inbound_dlq_lines_for_rekey(
                state_dir,
                &content,
                old_passphrase,
                new_passphrase,
                legacy_policy,
            )?;
            std::fs::rename(&live_path, &backup_path).map_err(|err| {
                dlq_io_failed(format!(
                    "rekey recovery: stash original DLQ at {}: {err}",
                    backup_path.display()
                ))
            })?;
            sync_dlq_parent_dir_or_err_blocking(&backup_path)?;
            if let Err(err) = replace_matrix_inbound_dlq_lines_blocking(&live_path, &new_lines) {
                let restore_result = restore_matrix_inbound_dlq_backup(&backup_path, &live_path);
                if let Err(restore_err) = restore_result {
                    return Err(dlq_io_failed(format!(
                        "rekey recovery: write rekeyed DLQ failed: {err}; additionally restoring OLD DLQ failed: {restore_err}"
                    )));
                }
                return Err(dlq_io_failed(format!(
                    "rekey recovery: write rekeyed DLQ failed and OLD DLQ was restored: {err}"
                )));
            }
            Ok(MatrixDlqRekeyOutcome::Rotated {
                decoded_count: new_lines.len(),
                backup_path,
            })
        }
        Some(_) | None => Ok(MatrixDlqRekeyOutcome::Skipped),
    }
}

/// Re-encrypt the inbound DLQ from the OLD passphrase-derived AEAD
/// key to the NEW passphrase-derived AEAD key. Called by
/// `cara matrix rekey-store --new` BEFORE the SQLite advance so a
/// rekey transaction never leaves DLQ records orphaned under the
/// old key. Returns `Skipped` for empty/missing DLQ, `Rotated` on
/// success (caller manages the backup), or `Err` on any line that
/// won't decode under the OLD key (operator must manually
/// quarantine before retry).
///
/// V1 (HKDF) records on disk are decoded under the OLD v1 key and
/// re-encoded as v2 under the NEW key — completing the v1→v2
/// rotation as part of the same transaction.
pub(crate) fn rotate_matrix_inbound_dlq_for_rekey(
    state_dir: &Path,
    config: &MatrixConfig,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<MatrixDlqRekeyOutcome, MatrixError> {
    let path = matrix_inbound_dlq_path(state_dir);
    let Some(original) = read_matrix_inbound_dlq_rekey_source(&path, "rekey")? else {
        return Ok(MatrixDlqRekeyOutcome::Skipped);
    };
    let new_lines = reencode_matrix_inbound_dlq_lines_for_rekey(
        state_dir,
        &original,
        old_passphrase,
        new_passphrase,
        config.legacy_dlq_envelope_policy,
    )?;
    // Stash the OLD ciphertext alongside under `.pre-rekey` so the
    // caller can restore it on a subsequent SQLite-advance failure.
    // Using a sibling file (atomic rename within the same dir) keeps
    // the rollback to a single rename syscall.
    let backup_path = matrix_inbound_dlq_rekey_backup_path(state_dir);
    std::fs::rename(&path, &backup_path).map_err(|err| {
        dlq_io_failed(format!(
            "rekey: failed to stash original DLQ at {}: {err}",
            backup_path.display()
        ))
    })?;
    sync_dlq_parent_dir_or_err_blocking(&backup_path)?;
    if let Err(err) = replace_matrix_inbound_dlq_lines_blocking(&path, &new_lines) {
        let restore_result = restore_matrix_inbound_dlq_backup(&backup_path, &path);
        if let Err(restore_err) = restore_result {
            return Err(dlq_io_failed(format!(
                "rekey: write rekeyed DLQ failed: {err}; additionally restoring OLD DLQ failed: {restore_err}"
            )));
        }
        return Err(dlq_io_failed(format!(
            "rekey: write rekeyed DLQ failed and OLD DLQ was restored: {err}"
        )));
    }
    Ok(MatrixDlqRekeyOutcome::Rotated {
        decoded_count: new_lines.len(),
        backup_path,
    })
}

pub(super) async fn dispatch_matrix_dlq_record(
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    state_dir: &Path,
    config: &MatrixConfig,
    record: &MatrixInboundDlqRecord,
) -> Result<(), MatrixError> {
    // Re-check the sender allowlist against the CURRENT (boot-time)
    // config, not the value captured when the record was appended.
    // An operator who removed a peer from `matrix.autoJoin` between
    // the original receive and the next successful replay tick
    // expects subsequent messages from that peer to be refused —
    // including stranded DLQ records. Treat refusal as
    // "dispatched-successfully-and-drop" so phase-3 removes the
    // record from the DLQ rather than leaving an un-dispatchable
    // entry that occupies cap forever.
    if !config.auto_join.allows_user(record.sender_id.as_str()) {
        let sender_log = sanitize_homeserver_identifier(record.sender_id.as_str());
        let event_id_log = sanitize_homeserver_identifier(record.event_id.as_str());
        warn!(
            sender = %sender_log,
            event_id = %event_id_log,
            "Matrix DLQ replay dropping record because sender no longer matches the current auto_join allowlist"
        );
        // SECURITY: the immediate caller (replay loop) treats Ok(()) as
        // "dispatched-successfully-drop-from-DLQ" so the merged_lines
        // rewrite commits without this record. That disk change is
        // IRREVERSIBLE. Use `audit_durable_for_state_dir` so the
        // forensic event is on disk BEFORE we tell the caller "done".
        // The prior `audit::audit()` call discarded the
        // AuditWriteOutcome — a saturated audit channel (Dropped) or
        // buffered-only (Enqueued + later writer failure) silently
        // erased the only record that this allowlist-drift decision
        // ever happened.
        // SECURITY: cap both fields through the audit free-text
        // truncator. `sanitize_homeserver_identifier` allows up to
        // 255 bytes per identifier, and the envelope plus two such
        // fields busts the macOS 512-byte line cap. Truncating here
        // lets both fit even at their longest legitimate length.
        crate::logging::audit::audit_durable_for_state_dir(
            state_dir.to_path_buf(),
            crate::logging::audit::AuditEvent::MatrixInboundDlqRecordDroppedAllowlistDrift {
                sender_id: crate::logging::audit::truncate_audit_free_text_field(
                    &sender_log,
                    crate::logging::audit::AUDIT_FREE_TEXT_FIELD_MAX_BYTES,
                ),
                event_id: crate::logging::audit::truncate_audit_free_text_field(
                    &event_id_log,
                    crate::logging::audit::AUDIT_FREE_TEXT_FIELD_MAX_BYTES,
                ),
            },
        )
        .map_err(|err| {
            dlq_io_failed(format!(
                "audit Matrix DLQ allowlist-drift drop: {err}; \
                 refusing to drop the record without durable forensic evidence"
            ))
        })?;
        return Ok(());
    }

    crate::channels::inbound::dispatch_inbound_text_with_options(
        &ws_state,
        MATRIX_CHANNEL_ID,
        record.sender_id.as_str(),
        record.room_id.as_str(),
        &record.text,
        Some(record.room_id.to_string()),
        crate::channels::inbound::InboundDispatchOptions {
            inbound_event_id: matrix_event_idempotency_key(record.event_id.as_str()),
            delivery_recipient_id: Some(record.room_id.to_string()),
            ..Default::default()
        },
    )
    .await
    .map(|result| {
        let mut guard = state.write();
        guard.record_inbound_dedupe_corrupt_lines(result.corrupt_dedupe_index_lines);
        guard.reset_inbound_failures();
    })
    .map_err(|err| {
        if err.is_session_history_corrupt() {
            MatrixError::SessionHistoryCorrupt(format!("replay Matrix inbound event: {err}"))
        } else {
            dlq_dispatch_failed(format!("replay Matrix inbound event: {err}"))
        }
    })
}

/// Single-record encode helper. Production callers route through
/// `encode_matrix_inbound_dlq_record_with_key` after fetching the
/// daemon-lifetime cache via `state.dlq_keys()`; this entry point
/// is retained for tests and ad-hoc one-off encodes that don't
/// have access to runtime state.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn encode_matrix_inbound_dlq_record(
    state_dir: &Path,
    config: &MatrixConfig,
    record: &MatrixInboundDlqRecord,
) -> Result<String, MatrixError> {
    if !config.encrypted() {
        return encode_matrix_inbound_dlq_record_with_key(None, record);
    }

    // Always emit v2 (Argon2id) on the write path. Existing v1
    // records on disk continue to decode through the read path's
    // dual-version branch, but new writes never produce v1.
    let key = derive_matrix_inbound_dlq_key(state_dir, config)?;
    encode_matrix_inbound_dlq_record_with_key(Some(&key), record)
}

/// Encode-with-key variant for hot loops that derive the AEAD key
/// once and process N records. The single-record entry point at
/// `encode_matrix_inbound_dlq_record` re-derives the key on every
/// call (one Argon2id derivation + one filesystem read of
/// `installation_id`); Argon2id is memory-hard and slow (tens of
/// ms per call), so calling it 10k times during a near-cap replay
/// would block every concurrent `append_matrix_inbound_dlq` for
/// several seconds under `dlq_io_lock`. Callers in the hot path
/// derive once and pass the key reference.
///
/// The supplied key is always treated as v2 (Argon2id) — the v1
/// path is read-only and only decode sees envelopes tagged
/// `MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY`.
pub(super) fn encode_matrix_inbound_dlq_record_with_key(
    key: Option<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>>,
    record: &MatrixInboundDlqRecord,
) -> Result<String, MatrixError> {
    // Wrap the serialized plaintext in `Zeroizing<Vec<u8>>` so the
    // intermediate buffer that holds the decrypted message body is
    // wiped before the heap allocation is returned to the allocator.
    // The struct's hand-rolled Drop-zeroize on `text` is undermined
    // without this — same plaintext, separate allocation, no zeroize.
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(record).map_err(|err| {
        dlq_serialization_failed(format!("serialize Matrix inbound DLQ record: {err}"))
    })?);
    let Some(key) = key else {
        // Plaintext branch: copy the bytes into a `String` for return.
        // The Zeroizing<Vec<u8>> is dropped at scope-end and zeroes
        // its bytes; the returned String contains a fresh allocation
        // that the caller is responsible for.
        return String::from_utf8(plaintext.to_vec())
            .map_err(|err| dlq_serialization_failed(format!("encode Matrix inbound DLQ: {err}")));
    };
    let aad = matrix_inbound_dlq_aad(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION);
    let blob = crate::crypto::encrypt_aead_blob(key, &plaintext, &aad)
        .map_err(|_| dlq_crypto_operation_failed("encrypt Matrix inbound DLQ"))?;
    serde_json::to_string(&MatrixEncryptedInboundDlqRecord {
        version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
        nonce: URL_SAFE_NO_PAD.encode(blob.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(blob.ciphertext),
    })
    .map_err(|err| {
        dlq_serialization_failed(format!("serialize encrypted Matrix inbound DLQ: {err}"))
    })
}

pub(super) fn matrix_inbound_dlq_aad(version: u8) -> Vec<u8> {
    format!("matrix-inbound-dlq-envelope-v{version}").into_bytes()
}

pub(super) fn matrix_inbound_dlq_envelope_version(line: &str) -> Option<u8> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    if !(value.get("version").is_some()
        && value.get("nonce").is_some()
        && value.get("ciphertext").is_some())
    {
        return None;
    }
    value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u8::try_from(version).ok())
}

pub(super) fn record_matrix_inbound_dlq_legacy_envelope_processed(
    state_dir: &Path,
    reencoded_count: usize,
    drained_count: usize,
    quarantined_count: usize,
) -> Result<(), MatrixError> {
    let record_count = reencoded_count
        .saturating_add(drained_count)
        .saturating_add(quarantined_count);
    if record_count == 0 {
        return Ok(());
    }

    // Policy: legacy-envelope migration is security-relevant forensic
    // evidence and MUST be on disk before the caller proceeds to the
    // irreversible DLQ rewrite. Use `audit_durable_for_state_dir` so
    // the audit event is synchronously flushed regardless of whether
    // the in-process AUDIT_LOG owns the state_dir — the prior
    // `audit_blocking_or_enqueue_for_state_dir` returned
    // `AuditWriteOutcome::Enqueued` when the writer owned the dir,
    // and accepting Enqueued meant the buffered event could still be
    // dropped by a later writer failure while the disk-side DLQ
    // changes had already committed (unaudited legacy processing).
    crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed {
            from_version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY,
            current_version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
            record_count,
            reencoded_count,
            drained_count,
            quarantined_count,
        },
    )
    .map_err(|err| {
        dlq_io_failed(format!(
            "audit Matrix inbound DLQ legacy envelope migration: {err}"
        ))
    })?;
    Ok(())
}

pub(super) fn decrypt_matrix_inbound_dlq_blob(
    key: &zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>,
    nonce: &[u8; crate::crypto::AEAD_NONCE_LEN],
    ciphertext: &[u8],
    version: u8,
) -> Result<Vec<u8>, MatrixError> {
    let aad = matrix_inbound_dlq_aad(version);
    match crate::crypto::decrypt_aead_blob(key, nonce, ciphertext, &aad) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) if version == MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY => {
            crate::crypto::decrypt_aead_blob(key, nonce, ciphertext, MATRIX_INBOUND_DLQ_AAD)
                .map_err(|_| {
                    dlq_crypto_operation_failed("decrypt Matrix inbound DLQ legacy AAD fallback")
                })
        }
        Err(_) => Err(dlq_crypto_operation_failed(
            "decrypt Matrix inbound DLQ primary AAD",
        )),
    }
}

/// Single-record entry point. Hot-loop callers (replay phase 1,
/// cap-clamp tail decode) MUST call
/// `decode_matrix_inbound_dlq_record_with_keys` to avoid re-deriving
/// the AEAD key per record. This single-record entry point derives
/// lazily inside the encrypted branch only and is retained for tests
/// + ad-hoc one-off decodes.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn decode_matrix_inbound_dlq_record(
    state_dir: &Path,
    config: &MatrixConfig,
    line: &str,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    decode_matrix_inbound_dlq_record_with_policy(
        state_dir,
        Some(config),
        line,
        None,
        config.legacy_dlq_envelope_policy,
    )
}

/// Decode the tail slice of a cap-clamp-truncated DLQ rewrite,
/// returning (decoded event_ids, decode_failure_count). Extracted
/// so a unit test can pin the wave-decode classification without
/// stuffing 10k records through the live replay path. Real-cap
/// (`MATRIX_INBOUND_DLQ_MAX_RECORDS = 10000`) is impractical to
/// hit in a test; the helper exercises the same accounting on a
/// small fixture.
///
/// `decode_failures > 0` with `dropped_ids.len() < tail.len()`
/// indicates undecodable records (typically a store-key mismatch
/// from a prior `CARAPACE_CONFIG_PASSWORD` rotation). The replay
/// loop surfaces this as a separate warn so operators investigate
/// key history rather than asking peers to resend events.
pub(super) fn collect_dropped_event_ids_from_tail(
    tail: &[String],
    keys: Option<&MatrixDlqKeys>,
) -> (Vec<String>, usize) {
    let mut decode_failures: usize = 0;
    let dropped_ids: Vec<String> = tail
        .iter()
        .filter_map(|line| {
            // Tail-truncate decode may encounter both v1 (if the
            // DLQ was upgraded mid-life) and v2 records; pass the
            // full key cache so each record decodes with the right
            // KDF.
            match decode_matrix_inbound_dlq_record_with_keys(keys, line) {
                Ok(record) => Some(sanitize_homeserver_identifier(record.event_id.as_str())),
                Err(err) => {
                    decode_failures += 1;
                    tracing::debug!(
                        error = %err,
                        "could not decode tail-truncated DLQ record for forensic \
                         event_id capture; record was already going to be dropped"
                    );
                    None
                }
            }
        })
        .collect();
    (dropped_ids, decode_failures)
}

/// Decode-with-keys variant for hot loops. The AEAD keys are
/// process-deterministic over `(passphrase, installation_id)`,
/// both fixed for a daemon's lifetime barring rekey. The cache
/// lives daemon-lifetime on `MatrixRuntimeState`; callers obtain
/// it via `state.dlq_keys()` and pre-populate via
/// `MatrixDlqKeys::ensure_v*` (the replay loop does this once at
/// the top of the encrypted-config branch). Argon2id (v2) is
/// memory-hard and ~100ms per derivation; without the daemon-
/// lifetime cache + pre-population, deriving 10k times during a
/// near-cap replay would block every concurrent
/// `append_matrix_inbound_dlq` under `dlq_io_lock`. Per-record
/// decode under this entry point performs zero key derivation —
/// it's a pointer load against the OnceLock-backed slots.
pub(super) fn decode_matrix_inbound_dlq_record_with_keys(
    keys: Option<&MatrixDlqKeys>,
    line: &str,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    decode_matrix_inbound_dlq_record_with_policy(
        Path::new(""),
        None,
        line,
        keys,
        MatrixLegacyDlqEnvelopePolicy::Accept,
    )
}

pub(super) fn decode_matrix_inbound_dlq_record_with_policy(
    state_dir: &Path,
    config: Option<&MatrixConfig>,
    line: &str,
    cached_keys: Option<&MatrixDlqKeys>,
    legacy_policy: MatrixLegacyDlqEnvelopePolicy,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    // Detect the on-disk format by introspecting the line rather than
    // trusting `config.encrypted()`. An operator who flipped
    // `matrix.encrypted` between runs (true→false, then back) would
    // otherwise leave existing records permanently unreplayable —
    // `serde_json::from_str::<MatrixInboundDlqRecord>` would parse the
    // envelope-shaped JSON as plaintext (and fail on missing fields),
    // and the reverse direction parses plaintext lines as envelopes
    // (and fails on missing version/nonce/ciphertext). The envelope
    // is uniquely identifiable by carrying all three of `version`,
    // `nonce`, `ciphertext` at the top level; `MatrixInboundDlqRecord`
    // has none of those.
    let line_is_encrypted = serde_json::from_str::<serde_json::Value>(line)
        .map(|v| {
            v.get("version").is_some() && v.get("nonce").is_some() && v.get("ciphertext").is_some()
        })
        .unwrap_or(false);
    let record = if !line_is_encrypted {
        serde_json::from_str::<MatrixInboundDlqRecord>(line).map_err(|err| {
            dlq_serialization_failed(format!("parse Matrix inbound DLQ record: {err}"))
        })?
    } else {
        let envelope: MatrixEncryptedInboundDlqRecord =
            serde_json::from_str(line).map_err(|err| {
                dlq_serialization_failed(format!(
                    "parse encrypted Matrix inbound DLQ record: {err}"
                ))
            })?;
        // Accept v1 (HKDF, legacy) and v2 (Argon2id, current).
        // Anything else is a wire-format mismatch — likely an
        // operator running a version pair where the on-disk
        // record was written by a NEWER carapace than the one
        // reading it.
        if envelope.version != MATRIX_INBOUND_DLQ_ENVELOPE_VERSION
            && envelope.version != MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY
        {
            return Err(dlq_serialization_failed(format!(
                "unsupported Matrix inbound DLQ version {}",
                envelope.version
            )));
        }
        if envelope.version == MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY
            && legacy_policy == MatrixLegacyDlqEnvelopePolicy::Refuse
        {
            return Err(legacy_dlq_envelope_refused(
                "v1 envelope rejected during Matrix inbound DLQ decode",
            ));
        }
        let nonce = decode_matrix_dlq_b64_fixed::<{ crate::crypto::AEAD_NONCE_LEN }>(
            "nonce",
            &envelope.nonce,
        )?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|err| {
                dlq_serialization_failed(format!(
                    "decode encrypted Matrix inbound DLQ ciphertext: {err}"
                ))
            })?;
        // Two key sources: the pre-derived cache (hot path) or
        // lazy derivation against the supplied `config`. If the
        // cache slot for this envelope's version is missing AND
        // no `config` was provided (the `_with_keys` API path),
        // return a typed `MatrixError` rather than panicking —
        // an operator who toggled `matrix.encrypted=true → false`
        // between runs would otherwise leave encrypted records on
        // disk that the cache doesn't pre-populate, and the panic
        // would loop the maintenance phase.
        let derived_v1;
        let derived_v2;
        let key = if envelope.version == MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY {
            match cached_keys.and_then(|k| k.v1()) {
                Some(k) => k,
                None => {
                    let cfg = config.ok_or_else(|| {
                        dlq_crypto_config_unavailable(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY)
                    })?;
                    let passphrase = resolve_matrix_store_passphrase(state_dir, cfg)?
                        .ok_or(MatrixError::MissingStoreSecret)?;
                    let installation_id = read_or_create_installation_id(state_dir)?;
                    derived_v1 = derive_matrix_inbound_dlq_key_v1_from(
                        passphrase.as_bytes(),
                        installation_id.as_bytes(),
                    )?;
                    &derived_v1
                }
            }
        } else {
            match cached_keys.and_then(|k| k.v2()) {
                Some(k) => k,
                None => {
                    let cfg = config.ok_or_else(|| {
                        dlq_crypto_config_unavailable(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION)
                    })?;
                    derived_v2 = derive_matrix_inbound_dlq_key(state_dir, cfg)?;
                    &derived_v2
                }
            }
        };
        let plaintext = zeroize::Zeroizing::new(decrypt_matrix_inbound_dlq_blob(
            key,
            &nonce,
            &ciphertext,
            envelope.version,
        )?);
        serde_json::from_slice::<MatrixInboundDlqRecord>(&plaintext).map_err(|err| {
            dlq_serialization_failed(format!("parse decrypted Matrix inbound DLQ: {err}"))
        })?
    };
    Ok(record)
}

pub(super) fn decode_matrix_dlq_b64_fixed<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], MatrixError> {
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        dlq_serialization_failed(format!(
            "decode encrypted Matrix inbound DLQ {field}: {err}"
        ))
    })?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        dlq_serialization_failed(format!(
            "encrypted Matrix inbound DLQ {field} has wrong length: expected {N}, got {}",
            decoded.len()
        ))
    })
}

/// Pre-derived AEAD keys for the Matrix inbound DLQ. Both HKDF
/// (v1) and Argon2id (v2) are deterministic over
/// `(passphrase, installation_id)`, both fixed for a daemon's
/// lifetime barring rekey. Argon2id is memory-hard and slow (tens
/// of ms per derivation at the configured cost parameters); the
/// `OnceLock` slots ensure each derivation runs at most once per
/// daemon process. The struct lives on `MatrixRuntimeState` and
/// is shared via `Arc` across replay ticks — moving from per-tick
/// derivation to daemon-lifetime caching eliminates a recurring
/// ~100ms CPU spike + ~64MB memory allocation on every replay
/// cycle that hits the encrypted path.
///
/// `v1` carries the legacy HKDF key used when the on-disk envelope
/// is `MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY`. `v2` carries
/// the Argon2id key used for all writes and reads of
/// `MATRIX_INBOUND_DLQ_ENVELOPE_VERSION` records. Fresh-install
/// daemons with no v1 records on disk never derive v1; fully-
/// drained daemons that haven't written a v2 yet never derive v2.
pub(crate) struct MatrixDlqKeys {
    pub(super) v1: std::sync::OnceLock<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>>,
    pub(super) v2: std::sync::OnceLock<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>>,
}

// Hand-rolled Debug — derived Debug would print the raw 32-byte
// AEAD key contents via `OnceLock<Zeroizing<[u8; 32]>>::Debug`
// (Zeroizing forwards Debug to the inner array, which derives
// Debug). A stray `tracing::debug!(?state, ...)` on
// `MatrixRuntimeState` (which derives Debug and embeds an Arc
// to this struct) would dump the DLQ AEAD key into operator
// logs. Mirror the `MatrixInboundDlqRecord` hand-roll pattern
// (above): print only the populated/unpopulated state, never
// the bytes.
impl std::fmt::Debug for MatrixDlqKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixDlqKeys")
            .field(
                "v1",
                &if self.v1.get().is_some() {
                    "<set>"
                } else {
                    "<unset>"
                },
            )
            .field(
                "v2",
                &if self.v2.get().is_some() {
                    "<set>"
                } else {
                    "<unset>"
                },
            )
            .finish()
    }
}

impl MatrixDlqKeys {
    pub(super) fn empty() -> Self {
        Self {
            v1: std::sync::OnceLock::new(),
            v2: std::sync::OnceLock::new(),
        }
    }

    /// Construct with pre-derived keys for both envelope versions.
    /// Used by the rekey-store path to inject OLD-side keys without
    /// going through `resolve_matrix_store_passphrase` (which would
    /// return the new pinned passphrase if the file already exists).
    pub(crate) fn from_pre_derived(
        v1: zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>,
        v2: zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>,
    ) -> Self {
        let keys = Self::empty();
        let _ = keys.v1.set(v1);
        let _ = keys.v2.set(v2);
        keys
    }

    /// Lazily derive (or return cached) the v1 (HKDF) key. Used
    /// only on the read path for legacy envelopes. Concurrent
    /// callers (matrix-sdk dispatches event handlers via
    /// `FuturesUnordered` so the append path can race the replay
    /// loop on a cold cache) may both derive — both compute
    /// identical bytes because the KDF is deterministic over
    /// `(passphrase, installation_id)`, and the loser's
    /// `OnceLock::set` returns Err which we ignore. The cost is
    /// at most a one-time double-derive at process startup; HKDF
    /// is microseconds so the duplicate is harmless.
    pub(super) fn ensure_v1(
        &self,
        state_dir: &Path,
        config: &MatrixConfig,
    ) -> Result<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
        if let Some(key) = self.v1.get() {
            return Ok(key);
        }
        let passphrase = resolve_matrix_store_passphrase(state_dir, config)?
            .ok_or(MatrixError::MissingStoreSecret)?;
        let installation_id = read_or_create_installation_id(state_dir)?;
        let derived = derive_matrix_inbound_dlq_key_v1_from(
            passphrase.as_bytes(),
            installation_id.as_bytes(),
        )?;
        let _ = self.v1.set(derived);
        Ok(self.v1.get().expect("OnceLock populated above"))
    }

    /// Lazily derive (or return cached) the v2 (Argon2id) key.
    /// Used for all writes and for reads of v2 envelopes.
    pub(super) fn ensure_v2(
        &self,
        state_dir: &Path,
        config: &MatrixConfig,
    ) -> Result<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
        if let Some(key) = self.v2.get() {
            return Ok(key);
        }
        let passphrase = resolve_matrix_store_passphrase(state_dir, config)?
            .ok_or(MatrixError::MissingStoreSecret)?;
        let installation_id = read_or_create_installation_id(state_dir)?;
        let derived = derive_matrix_inbound_dlq_key_v2_from(
            passphrase.as_bytes(),
            installation_id.as_bytes(),
        )?;
        let _ = self.v2.set(derived);
        Ok(self.v2.get().expect("OnceLock populated above"))
    }

    /// Read accessors for the inner decode dispatch. Returns the
    /// already-cached key if populated, `None` otherwise — the
    /// canonical-entry path uses these to detect lazy-init misses
    /// and fall back to the synchronous derive helpers.
    pub(super) fn v1(&self) -> Option<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>> {
        self.v1.get()
    }

    pub(super) fn v2(&self) -> Option<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>> {
        self.v2.get()
    }
}

/// Compatibility alias. Existing call sites that take a single
/// pre-derived AEAD key (the `Some(&Zeroizing<[u8; AEAD_KEY_LEN]>)`
/// shape) still work — they're now strictly the v2 (Argon2id) path.
pub(super) fn derive_matrix_inbound_dlq_key(
    state_dir: &Path,
    config: &MatrixConfig,
) -> Result<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
    let passphrase = resolve_matrix_store_passphrase(state_dir, config)?
        .ok_or(MatrixError::MissingStoreSecret)?;
    let installation_id = read_or_create_installation_id(state_dir)?;
    derive_matrix_inbound_dlq_key_v2_from(passphrase.as_bytes(), installation_id.as_bytes())
}

/// Pure HKDF-SHA256 derivation — the legacy v1 wire format.
/// Retained so existing on-disk DLQ records (encoded under v1)
/// continue to decode after upgrade. New writes go through
/// `derive_matrix_inbound_dlq_key_v2_from`.
pub(super) fn derive_matrix_inbound_dlq_key_v1_from(
    passphrase: &[u8],
    installation_id: &[u8],
) -> Result<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
    let hk = Hkdf::<Sha256>::new(Some(installation_id), passphrase);
    // Same Zeroize discipline as `derive_matrix_store_key` — the
    // AEAD key for DLQ blobs never sits unzeroed on the stack.
    let mut key = zeroize::Zeroizing::new([0u8; crate::crypto::AEAD_KEY_LEN]);
    hk.expand(MATRIX_INBOUND_DLQ_INFO, &mut *key)
        .map_err(|_| MatrixError::StoreKeyDerivation)?;
    Ok(key)
}

/// Argon2id derivation — the v2 wire format. Memory-hard KDF that
/// raises offline brute-force on `CARAPACE_CONFIG_PASSWORD` from
/// HKDF-fast (microseconds per guess) to memory-bound (tens of ms
/// per guess at the configured cost parameters in
/// `crate::crypto::derive_key_argon2id`). The salt is the
/// per-installation `installation_id`, which is at least 16 bytes
/// (UUID hex form is ~36 bytes), satisfying
/// `PASSWORD_KDF_MIN_SALT_LEN`.
///
/// The Argon2id parameters live in one place
/// (`crate::crypto::derive_key_argon2id`) and are shared with the
/// sealed-config-secret derivation. A future parameter rotation
/// requires bumping `MATRIX_INBOUND_DLQ_ENVELOPE_VERSION` to a
/// new value (v3) so the readers know which parameters to use.
pub(super) fn derive_matrix_inbound_dlq_key_v2_from(
    passphrase: &[u8],
    installation_id: &[u8],
) -> Result<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
    let raw = crate::crypto::derive_key_argon2id(passphrase, installation_id)
        .map_err(|_| MatrixError::StoreKeyDerivation)?;
    Ok(zeroize::Zeroizing::new(raw))
}

/// Re-exported with the legacy name so the existing pinned test
/// vector at `test_pinned_matrix_inbound_dlq_key_vector` keeps
/// asserting the v1 derivation against drift. The v2 derivation
/// has its own pin below.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn derive_matrix_inbound_dlq_key_from(
    passphrase: &[u8],
    installation_id: &[u8],
) -> Result<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
    derive_matrix_inbound_dlq_key_v1_from(passphrase, installation_id)
}

pub(super) async fn append_matrix_inbound_dlq_line(
    path: &Path,
    line: String,
) -> Result<(), MatrixError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || append_matrix_inbound_dlq_line_blocking(&path, &line))
        .await
        .map_err(|err| dlq_io_failed(format!("Matrix inbound DLQ append task: {err}")))?
}

#[cfg(unix)]
pub(super) fn append_matrix_inbound_dlq_line_blocking(
    path: &Path,
    line: &str,
) -> Result<(), MatrixError> {
    use std::io::Write;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};

    let existed = path.exists();
    // SECURITY: O_NOFOLLOW + O_NONBLOCK. O_NOFOLLOW prevents a same-
    // uid attacker who shares the daemon's `state_dir/matrix/` from
    // pre-planting a symlink at the DLQ path and redirecting our
    // (encrypted) DLQ writes elsewhere. O_NONBLOCK prevents
    // `O_CREAT | O_WRONLY | O_APPEND` from hanging on a planted
    // FIFO with no reader — the post-open file-type refusal below
    // only fires AFTER open(2) returns. Same lesson as the B99
    // sweep; this site was missed.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| dlq_io_failed(format!("open Matrix inbound DLQ: {err}")))?;
    // Post-open validation: ensure the dirent we opened is a regular
    // file. O_NOFOLLOW handles the symlink case; this catches FIFO /
    // socket / device-node pre-plants. (Linux's open(2) refuses these
    // for O_APPEND on most kernels but not universally.)
    let opened_metadata = file
        .metadata()
        .map_err(|err| dlq_io_failed(format!("stat Matrix inbound DLQ: {err}")))?;
    let file_type = opened_metadata.file_type();
    if !file_type.is_file()
        || file_type.is_symlink()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(dlq_io_failed(format!(
            "Matrix inbound DLQ path is not a regular file: {}",
            path.display()
        )));
    }
    if existed {
        let mut permissions = opened_metadata.permissions();
        if permissions.mode() & 0o777 != 0o600 {
            permissions.set_mode(0o600);
            file.set_permissions(permissions)
                .map_err(|err| dlq_io_failed(format!("chmod Matrix inbound DLQ: {err}")))?;
        }
    }
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| dlq_io_failed(format!("write Matrix inbound DLQ: {err}")))?;
    if !existed {
        sync_dlq_parent_dir_or_err_blocking(path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn append_matrix_inbound_dlq_line_blocking(
    path: &Path,
    line: &str,
) -> Result<(), MatrixError> {
    use std::io::Write;

    let existed = path.exists();
    // SECURITY: on Windows there is no exact O_NOFOLLOW equivalent.
    // Pre-check via `symlink_metadata` if the path exists to refuse
    // a symlink/reparse-point pre-plant; the residual race window
    // (post-check, pre-open) is acceptable on a platform that the
    // Matrix channel explicitly refuses to enable encrypted state
    // on (see `ensure_encrypted_matrix_state_supported_on_platform`).
    if existed {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|err| dlq_io_failed(format!("stat Matrix inbound DLQ: {err}")))?;
        if metadata.file_type().is_symlink() {
            return Err(dlq_io_failed(format!(
                "Matrix inbound DLQ path is a symlink, refusing to follow: {}",
                path.display()
            )));
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| dlq_io_failed(format!("open Matrix inbound DLQ: {err}")))?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| dlq_io_failed(format!("write Matrix inbound DLQ: {err}")))?;
    if !existed {
        sync_dlq_parent_dir_or_err_blocking(path)?;
    }
    Ok(())
}

pub(super) async fn replace_matrix_inbound_dlq_lines(
    path: &Path,
    lines: Vec<String>,
) -> Result<(), MatrixError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || replace_matrix_inbound_dlq_lines_blocking(&path, &lines))
        .await
        .map_err(|err| dlq_io_failed(format!("Matrix inbound DLQ rewrite task: {err}")))?
}

#[cfg(unix)]
pub(super) fn replace_matrix_inbound_dlq_lines_blocking(
    path: &Path,
    lines: &[String],
) -> Result<(), MatrixError> {
    use std::io::Write;

    if lines.is_empty() {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(dlq_io_failed(format!(
                    "remove drained Matrix inbound DLQ: {err}"
                )));
            }
        }
        sync_dlq_parent_dir_or_err_blocking(path)?;
        return Ok(());
    }

    let tmp_path = matrix_inbound_dlq_temp_path(path);
    let write_result = (|| {
        // Route through the canonical helper for O_NOFOLLOW + O_EXCL +
        // 0o600 defense-in-depth.
        let mut file = crate::paths::create_atomic_tmp_owner_only(&tmp_path)
            .map_err(|err| dlq_io_failed(format!("create Matrix inbound DLQ temp: {err}")))?;
        for line in lines {
            file.write_all(line.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|err| dlq_io_failed(format!("write Matrix inbound DLQ temp: {err}")))?;
        }
        file.sync_all()
            .map_err(|err| dlq_io_failed(format!("sync Matrix inbound DLQ temp: {err}")))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|err| dlq_io_failed(format!("replace Matrix inbound DLQ: {err}")))?;
        // Propagate fsync errors. A silent failure here would let an
        // empty-on-rename DLQ replay-rewrite revert to the OLD file
        // on power loss, re-dispatching events the session-history
        // dedupe might miss if the session file is also affected.
        sync_dlq_parent_dir_or_err_blocking(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

#[cfg(not(unix))]
pub(super) fn replace_matrix_inbound_dlq_lines_blocking(
    path: &Path,
    lines: &[String],
) -> Result<(), MatrixError> {
    use std::io::Write;

    if lines.is_empty() {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(dlq_io_failed(format!(
                    "remove drained Matrix inbound DLQ: {err}"
                )));
            }
        }
        sync_dlq_parent_dir_or_err_blocking(path)?;
        return Ok(());
    }

    let tmp_path = matrix_inbound_dlq_temp_path(path);
    let write_result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|err| dlq_io_failed(format!("create Matrix inbound DLQ temp: {err}")))?;
        for line in lines {
            file.write_all(line.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|err| dlq_io_failed(format!("write Matrix inbound DLQ temp: {err}")))?;
        }
        file.sync_all()
            .map_err(|err| dlq_io_failed(format!("sync Matrix inbound DLQ temp: {err}")))?;
        if path.exists() {
            std::fs::remove_file(path).map_err(|err| {
                dlq_io_failed(format!(
                    "remove old Matrix inbound DLQ before replace: {err}"
                ))
            })?;
        }
        std::fs::rename(&tmp_path, path)
            .map_err(|err| dlq_io_failed(format!("replace Matrix inbound DLQ: {err}")))?;
        // Same C4 propagation as the Unix branch — see the explanation
        // there.
        sync_dlq_parent_dir_or_err_blocking(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}
fn matrix_inbound_dlq_temp_path(path: &Path) -> PathBuf {
    crate::paths::atomic_tmp_path(path, "secret")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::matrix::{
        matrix_rs_fn_body, matrix_test_config, matrix_test_config_with_passphrase,
    };
    use std::path::Path;

    /// Pin `matrix_inbound_dlq_line_count` returns `Ok(None)` when
    /// the file doesn't exist. Append paths call this before opening
    /// the file; a missing file means "no DLQ entries yet, fine to
    /// proceed."
    #[tokio::test]
    async fn test_matrix_inbound_dlq_line_count_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.jsonl");
        let result = matrix_inbound_dlq_line_count(&path).await.unwrap();
        assert_eq!(result, None);
    }

    /// Pin the byte-floor short-circuit: a file below the
    /// `CAP_BYTES_FLOOR` heuristic returns `Some(0)` without doing
    /// any content I/O. This is the hot-path optimization that
    /// prevents holding dlq_io_lock during full-file reads on the
    /// common (well-below-cap) case.
    #[tokio::test]
    async fn test_matrix_inbound_dlq_line_count_below_floor_returns_zero_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("below_floor.jsonl");
        // Write a small file (well below CAP_BYTES_FLOOR = 10_000 *
        // 100 = 1 MB). A 4-line file is ~50 bytes total.
        tokio::fs::write(&path, b"a\nb\nc\nd\n").await.unwrap();
        let result = matrix_inbound_dlq_line_count(&path).await.unwrap();
        // Sentinel `Some(0)` short-circuit — the function did NOT
        // read content. The caller compares `>= MAX_RECORDS`, so 0
        // is structurally safe.
        assert_eq!(
            result,
            Some(0),
            "below-floor file must short-circuit to Some(0)"
        );
    }

    /// Pin the above-floor full-read path: when the byte size
    /// crosses the heuristic floor, the function reads the file and
    /// counts newlines for an exact count (with early-exit at
    /// MAX_RECORDS).
    #[tokio::test]
    async fn test_matrix_inbound_dlq_line_count_above_floor_counts_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("above_floor.jsonl");
        // Write a file just over CAP_BYTES_FLOOR with a known line
        // count. CAP_BYTES_FLOOR = 10_000 * 100 = 1_000_000 bytes.
        // Use 110-byte lines × 10_001 lines = ~1.1 MB, above floor.
        let line = "x".repeat(109) + "\n"; // 110 bytes
        let line_count = 10_001;
        let mut content = String::with_capacity(line.len() * line_count);
        for _ in 0..line_count {
            content.push_str(&line);
        }
        tokio::fs::write(&path, content.as_bytes()).await.unwrap();

        let result = matrix_inbound_dlq_line_count(&path).await.unwrap();
        // The function early-exits once `count > MAX_RECORDS`, so
        // the returned value is `MAX_RECORDS + 1` (10_001) not the
        // total line count. Either way it triggers the cap branch
        // in the caller's `>= MAX_RECORDS` check.
        let count = result.expect("above-floor must produce Some(_)");
        assert!(
            count >= MATRIX_INBOUND_DLQ_MAX_RECORDS,
            "above-floor count must be >= {} for cap branch to fire; got {count}",
            MATRIX_INBOUND_DLQ_MAX_RECORDS
        );
    }
    #[derive(Default)]
    struct RecordingDlqDispatcher {
        records: ParkingMutex<Vec<MatrixInboundDlqRecord>>,
        fail_dispatch: bool,
    }
    impl RecordingDlqDispatcher {
        fn failing() -> Self {
            Self {
                records: ParkingMutex::new(Vec::new()),
                fail_dispatch: true,
            }
        }

        fn records(&self) -> Vec<MatrixInboundDlqRecord> {
            self.records.lock().clone()
        }
    }
    #[async_trait::async_trait]
    impl MatrixDlqDispatcher for RecordingDlqDispatcher {
        async fn dispatch(
            &self,
            _ws_state: Arc<WsServerState>,
            _state: Arc<RwLock<MatrixRuntimeState>>,
            _state_dir: &Path,
            _config: &MatrixConfig,
            record: &MatrixInboundDlqRecord,
        ) -> Result<(), MatrixError> {
            self.records.lock().push(record.clone());
            if self.fail_dispatch {
                Err(dlq_dispatch_failed("scripted DLQ dispatch failure"))
            } else {
                Ok(())
            }
        }
    }
    fn matrix_test_dlq_record() -> MatrixInboundDlqRecord {
        MatrixInboundDlqRecord {
            event_id: "$event:example.com".to_string(),
            room_id: "!room:example.com".to_string(),
            sender_id: "@alice:example.com".to_string(),
            text: "encrypted room secret".to_string(),
            received_at: 1_700_000_000_000,
        }
    }
    fn encode_legacy_v1_matrix_inbound_dlq_record_for_test(
        state_dir: &Path,
        config: &MatrixConfig,
        record: &MatrixInboundDlqRecord,
    ) -> String {
        let installation_id = read_or_create_installation_id(state_dir).expect("installation_id");
        let passphrase = resolve_matrix_store_passphrase(state_dir, config)
            .expect("resolve")
            .expect("passphrase present");
        let v1_key = derive_matrix_inbound_dlq_key_v1_from(
            passphrase.as_bytes(),
            installation_id.as_bytes(),
        )
        .expect("v1 derive");

        let plaintext = serde_json::to_vec(record).expect("serialize record");
        let blob = crate::crypto::encrypt_aead_blob(&v1_key, &plaintext, MATRIX_INBOUND_DLQ_AAD)
            .expect("encrypt v1");
        serde_json::to_string(&MatrixEncryptedInboundDlqRecord {
            version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY,
            nonce: URL_SAFE_NO_PAD.encode(blob.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(blob.ciphertext),
        })
        .expect("serialize v1 envelope")
    }

    #[test]
    fn test_matrix_inbound_dlq_encrypts_records_when_matrix_encrypted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let record = matrix_test_dlq_record();

        let line = encode_matrix_inbound_dlq_record(temp.path(), &config, &record)
            .expect("encrypted DLQ line");

        assert!(
            !line.contains(&record.text),
            "encrypted Matrix DLQ line must not persist plaintext message body"
        );
        assert!(
            !line.contains(record.sender_id.as_str()),
            "encrypted Matrix DLQ line must not persist plaintext sender"
        );
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &config, &line)
            .expect("encrypted DLQ line should decode");
        assert_eq!(decoded, record);
    }

    /// Pin the v1 wire shape (HKDF) and verify v2 readers decode it
    /// correctly. Operators upgrading carapace should NOT need to
    /// drain the DLQ first — existing v1-encoded records on disk
    /// must keep decoding through the dual-version branch.
    #[test]
    fn test_matrix_inbound_dlq_decodes_legacy_v1_envelope() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let record = matrix_test_dlq_record();

        let v1_line =
            encode_legacy_v1_matrix_inbound_dlq_record_for_test(temp.path(), &config, &record);

        // v2-deployed reader decodes the v1 line.
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &config, &v1_line)
            .expect("v1 envelope must decode under v2 reader");
        assert_eq!(decoded, record);
    }

    #[test]
    fn test_matrix_inbound_dlq_refuses_legacy_v1_when_policy_refuse() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = matrix_test_config(true);
        config.legacy_dlq_envelope_policy = MatrixLegacyDlqEnvelopePolicy::Refuse;
        let record = matrix_test_dlq_record();

        let v1_line =
            encode_legacy_v1_matrix_inbound_dlq_record_for_test(temp.path(), &config, &record);

        let err = decode_matrix_inbound_dlq_record(temp.path(), &config, &v1_line)
            .expect_err("operator-refuse policy must reject legacy v1 envelopes");

        assert!(matches!(err, MatrixError::LegacyDlqEnvelopeRefused(_)));
        assert!(
            err.to_string()
                .contains("legacy Matrix inbound DLQ v1 envelope refused by policy"),
            "unexpected error: {err}"
        );
        // Post-Batch-79: refused-legacy records are NOT classified as
        // temporarily-undecodable any more. `policy=Refuse` is the
        // operator's explicit choice and no toggle makes them
        // decodable later — so the replay loop routes them to
        // quarantine (Corrupt) for operator-attended forensic
        // preservation rather than the live-DLQ "preserved last"
        // tail-truncation class that silently drops under cap pressure.
        assert!(
            !is_temporarily_undecodable_dlq_error(&err),
            "refused legacy records must NOT be classified as temporarily-undecodable; they belong in quarantine, not the live DLQ tail"
        );
    }

    #[test]
    fn test_legacy_refused_replay_aggregate_preserves_detail() {
        let detail =
            "Matrix inbound DLQ replay still has 2 undelivered or undecodable record(s); first 3: legacy refused; io failed"
                .to_string();

        let class = classify_dlq_replay_error(&legacy_dlq_envelope_refused("refused legacy v1"));
        assert_eq!(
            class,
            DlqReplayErrorClass::LegacyRefused,
            "legacy-refused records must keep their operator-policy kind"
        );

        let err = dlq_replay_aggregate_error(class, detail.clone());
        let MatrixError::LegacyDlqEnvelopeRefused(message) = err else {
            panic!("legacy-refused aggregate must preserve replay detail, got {err:?}");
        };
        assert_eq!(message, detail);
    }

    #[test]
    fn test_dlq_io_priority_outranks_legacy_refusal() {
        let mut class = Some(DlqReplayErrorClass::LegacyRefused);
        merge_dlq_replay_error_class(&mut class, DlqReplayErrorClass::Crypto);
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::Crypto),
            "DLQ crypto failures must not be hidden behind policy refusal"
        );

        merge_dlq_replay_error_class(
            &mut class,
            DlqReplayErrorClass::CryptoConfigUnavailable { version: Some(2) },
        );
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::CryptoConfigUnavailable { version: Some(2) }),
            "a recoverable config-unavailable crypto subtype must not be erased by a generic crypto aggregate"
        );

        merge_dlq_replay_error_class(&mut class, DlqReplayErrorClass::LegacyRefused);
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::CryptoConfigUnavailable { version: Some(2) }),
            "a later legacy-refused record must not downgrade a crypto/config aggregate"
        );

        merge_dlq_replay_error_class(
            &mut class,
            DlqReplayErrorClass::CryptoConfigUnavailable { version: Some(1) },
        );
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::CryptoConfigUnavailable { version: None }),
            "mixed v1/v2 config-unavailable records must preserve that multiple DLQ envelope versions are affected"
        );

        merge_dlq_replay_error_class(&mut class, DlqReplayErrorClass::CapSaturation);
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::CapSaturation),
            "cap saturation must not be hidden behind policy refusal or crypto failures"
        );

        merge_dlq_replay_error_class(&mut class, DlqReplayErrorClass::LegacyRefused);
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::CapSaturation),
            "a later legacy-refused record must not downgrade a cap-saturation aggregate"
        );

        merge_dlq_replay_error_class(&mut class, DlqReplayErrorClass::Io);
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::Io),
            "infrastructure I/O failures must not be hidden behind policy refusal, crypto, or cap saturation"
        );

        merge_dlq_replay_error_class(&mut class, DlqReplayErrorClass::LegacyRefused);
        assert_eq!(
            class,
            Some(DlqReplayErrorClass::Io),
            "a later legacy-refused record must not downgrade an I/O aggregate"
        );
    }

    #[test]
    fn test_dlq_replay_error_class_priority_order_is_stable() {
        let ordered = [
            DlqReplayErrorClass::Dispatch,
            DlqReplayErrorClass::SessionHistory,
            DlqReplayErrorClass::Serialization,
            DlqReplayErrorClass::LegacyRefused,
            DlqReplayErrorClass::Crypto,
            DlqReplayErrorClass::CapSaturation,
            DlqReplayErrorClass::Io,
        ];
        assert_eq!(
            dlq_replay_error_class_priority(DlqReplayErrorClass::Crypto),
            dlq_replay_error_class_priority(DlqReplayErrorClass::CryptoConfigUnavailable {
                version: Some(2)
            }),
            "config-unavailable is a machine-readable DLQ crypto subtype, not a separate priority band"
        );

        for pair in ordered.windows(2) {
            assert!(
                dlq_replay_error_class_priority(pair[0]) < dlq_replay_error_class_priority(pair[1]),
                "{:?} must remain lower priority than {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_matrix_inbound_dlq_replay_rewrites_legacy_v1_with_audit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let record = matrix_test_dlq_record();
        let v1_line =
            encode_legacy_v1_matrix_inbound_dlq_record_for_test(temp.path(), &config, &record);
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&path, format!("{v1_line}\n")).expect("write legacy DLQ");

        let session_root = temp.path().join("sessions-file");
        std::fs::write(&session_root, b"not a directory").expect("seed session-store blocker");
        let session_store = Arc::new(crate::sessions::SessionStore::with_base_path(session_root));
        let ws_state = Arc::new(
            crate::server::ws::WsServerState::new(crate::server::ws::WsServerConfig::default())
                .with_session_store(session_store),
        );
        let err = replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state)
            .await
            .expect_err("dispatch is intentionally unwired, so record remains for retry");
        assert!(
            err.to_string()
                .contains("Matrix inbound DLQ replay still has"),
            "unexpected replay error: {err}"
        );

        let rewritten = std::fs::read_to_string(&path).expect("read rewritten DLQ");
        let envelope: MatrixEncryptedInboundDlqRecord =
            serde_json::from_str(rewritten.trim()).expect("rewritten encrypted envelope");
        assert_eq!(
            envelope.version, MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
            "legacy v1 record must be rewritten as the current DLQ envelope"
        );
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &config, rewritten.trim())
            .expect("rewritten v2 line must decode");
        assert_eq!(decoded, record);

        let audit = std::fs::read_to_string(temp.path().join("audit.jsonl"))
            .expect("legacy DLQ processing must leave audit evidence");
        let entry: crate::logging::audit::AuditEntry =
            serde_json::from_str(audit.lines().next().expect("audit line")).unwrap();
        assert_eq!(entry.event, "matrix_inbound_dlq_legacy_envelope_processed");
        assert_eq!(entry.data["from_version"], serde_json::json!(1));
        assert_eq!(entry.data["current_version"], serde_json::json!(2));
        assert_eq!(entry.data["record_count"], serde_json::json!(1));
        assert_eq!(entry.data["reencoded_count"], serde_json::json!(1));
    }

    /// New writes always emit v2 (Argon2id). A reader can confirm
    /// the wire shape by parsing the envelope and inspecting the
    /// `version` field.
    #[test]
    fn test_matrix_inbound_dlq_writes_emit_v2_envelope() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let record = matrix_test_dlq_record();

        let line = encode_matrix_inbound_dlq_record(temp.path(), &config, &record)
            .expect("encrypted DLQ line");
        let envelope: MatrixEncryptedInboundDlqRecord =
            serde_json::from_str(&line).expect("parse envelope");
        assert_eq!(
            envelope.version, MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
            "new writes must emit the current envelope version (v2 / Argon2id)"
        );
        assert_eq!(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION, 2);
        assert_eq!(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY, 1);
    }

    #[test]
    fn test_matrix_inbound_dlq_aad_binds_envelope_version_for_new_records() {
        let key = zeroize::Zeroizing::new([7u8; crate::crypto::AEAD_KEY_LEN]);
        let plaintext = b"{\"event_id\":\"$event:example.com\"}";
        let aad = matrix_inbound_dlq_aad(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION);
        assert_eq!(
            aad, b"matrix-inbound-dlq-envelope-v2",
            "v2 AAD is a released wire-format input and must not drift under version 2"
        );
        let blob = crate::crypto::encrypt_aead_blob(&key, plaintext, &aad).expect("encrypt");

        let decoded = decrypt_matrix_inbound_dlq_blob(
            &key,
            &blob.nonce,
            &blob.ciphertext,
            MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
        )
        .expect("current version AAD should decrypt");
        assert_eq!(decoded.as_slice(), plaintext);

        let err = decrypt_matrix_inbound_dlq_blob(
            &key,
            &blob.nonce,
            &blob.ciphertext,
            MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY,
        )
        .expect_err("new records must not decrypt under a different envelope version");
        assert!(
            err.to_string()
                .contains("decrypt Matrix inbound DLQ legacy AAD fallback"),
            "expected AAD-bound decrypt failure, got {err}"
        );
    }

    #[test]
    fn test_matrix_inbound_dlq_rejects_legacy_aad_v2_envelope() {
        let key = zeroize::Zeroizing::new([9u8; crate::crypto::AEAD_KEY_LEN]);
        let plaintext = b"{\"event_id\":\"$event:example.com\"}";
        let blob = crate::crypto::encrypt_aead_blob(&key, plaintext, MATRIX_INBOUND_DLQ_AAD)
            .expect("legacy encrypt");

        let err = decrypt_matrix_inbound_dlq_blob(
            &key,
            &blob.nonce,
            &blob.ciphertext,
            MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
        )
        .expect_err("legacy-AAD fallback must be restricted to v1 envelopes");

        assert!(err
            .to_string()
            .contains("decrypt Matrix inbound DLQ primary AAD"));
    }

    #[test]
    fn test_matrix_encrypted_inbound_dlq_record_rejects_unknown_fields() {
        let payload = serde_json::json!({
            "version": MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
            "nonce": "nonce",
            "ciphertext": "ciphertext",
            "futureField": true,
        });

        let result = serde_json::from_value::<MatrixEncryptedInboundDlqRecord>(payload);

        assert!(
            result.is_err(),
            "encrypted DLQ envelopes must reject unknown persisted fields"
        );
    }

    #[test]
    fn test_replace_matrix_inbound_dlq_lines_removes_file_when_drained() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().unwrap()).expect("create matrix dir");
        std::fs::write(&path, "record\n").expect("write live dlq");

        replace_matrix_inbound_dlq_lines_blocking(&path, &[]).expect("drain live dlq");

        assert!(
            !path.exists(),
            "draining every inbound DLQ record should remove the live file"
        );
    }

    /// Cross-version round-trip: encode-as-v2 → decode-via-shared-
    /// reader should not silently confuse with a v1 record. A v2
    /// envelope decoded under a hypothetical "v1-only reader" would
    /// mis-derive the key and AEAD tag mismatch would surface as
    /// `decrypt Matrix inbound DLQ`. Pin that the v2 reader does
    /// NOT accidentally decode under v1's KDF.
    #[test]
    fn test_matrix_inbound_dlq_v2_record_does_not_decode_with_v1_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let record = matrix_test_dlq_record();

        let line =
            encode_matrix_inbound_dlq_record(temp.path(), &config, &record).expect("v2 line");
        // Maliciously rewrite the version to v1 so the reader
        // would attempt v1 (HKDF) decryption against v2 (Argon2id)
        // ciphertext. AEAD tag mismatch must surface as a decrypt
        // error, not silent garbage.
        let mut envelope: MatrixEncryptedInboundDlqRecord =
            serde_json::from_str(&line).expect("parse v2 envelope");
        envelope.version = MATRIX_INBOUND_DLQ_ENVELOPE_VERSION_LEGACY;
        let tampered = serde_json::to_string(&envelope).expect("re-serialize");

        let err = decode_matrix_inbound_dlq_record(temp.path(), &config, &tampered)
            .expect_err("v2 ciphertext under v1 KDF must fail to decrypt");
        let msg = err.to_string();
        assert!(
            msg.contains("decrypt Matrix inbound DLQ"),
            "expected AEAD decrypt failure, got: {msg}"
        );
    }

    /// Adversary-reachable replay-loop DoS regression. Pre-fix the
    /// replay loop scanned all on-disk lines for the literal
    /// substring `"version":1` / `"version":2` regardless of
    /// `config.encrypted()`. A peer-controlled inbound message body
    /// (which JSON-encodes inside the plaintext DLQ record's
    /// `text` field) carrying that literal substring would force
    /// `ensure_v2`, which fails with `MissingStoreSecret` in
    /// plaintext config (no passphrase resolvable). Replay then
    /// aborts phase 1, the dlq_replay streak goes sticky, and the
    /// channel pins in Error indefinitely. The fix gates the scan
    /// on `config.encrypted()` so plaintext mode never derives —
    /// any encrypted-shape lines surface as per-record corrupt
    /// during decode and get quarantined.
    #[tokio::test(flavor = "current_thread")]
    async fn test_replay_plaintext_config_with_version_substring_in_body() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        // Append a plaintext record whose body carries the literal
        // substring `"version":2`. JSON-encodes as a normal string.
        let record = MatrixInboundDlqRecord {
            event_id: "$evt:example.com".to_string(),
            room_id: "!room:example.com".to_string(),
            sender_id: "@alice:example.com".to_string(),
            text: r#"discusses "version":2 of the spec"#.to_string(),
            received_at: 1_700_000_000_000,
        };
        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append plaintext record with substring body");

        // Replay must NOT fail with MissingStoreSecret. With the
        // fix, no derivation runs in plaintext mode regardless of
        // body bytes. The dispatch will fail (no ws state / no
        // session machinery wired here), but that failure path is
        // separate from the DoS regression we're pinning. The pin
        // is: replay does NOT short-circuit with MissingStoreSecret.
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let result = replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone()).await;

        // Even if dispatch fails, the error must NOT be MissingStoreSecret.
        // Acceptable shapes:
        //  - Ok(()) (replay succeeded; dispatch wasn't actually invoked)
        //  - Err(DlqDispatchFailure(_)) carrying dispatch failure
        // NOT acceptable: Err(MatrixError::MissingStoreSecret).
        if let Err(err) = &result {
            assert!(
                !matches!(err, MatrixError::MissingStoreSecret),
                "plaintext replay must NOT short-circuit with \
                 MissingStoreSecret on body-substring match: {err:?}"
            );
        }
    }

    /// `MatrixDlqKeys` Debug impl must NOT print the cached AEAD
    /// key bytes. Hand-rolled per `MatrixInboundDlqRecord` discipline:
    /// a future contributor adding `#[derive(Debug)]` would silently
    /// regress AEAD-key-leak protection. The leak only manifests
    /// when `tracing::debug!(?state, ...)` runs against a populated
    /// runtime — invisible at compile time, devastating in operator
    /// logs.
    #[test]
    fn test_matrix_dlq_keys_debug_does_not_print_key_bytes() {
        // Construct a key with a distinctive byte pattern so we
        // can assert its absence in the Debug output.
        let keys = MatrixDlqKeys::empty();
        let pattern: [u8; crate::crypto::AEAD_KEY_LEN] = [0xAB; crate::crypto::AEAD_KEY_LEN];
        let _ = keys.v2.set(zeroize::Zeroizing::new(pattern));

        let dbg = format!("{keys:?}");
        // The summary must surface set/unset state.
        assert!(
            dbg.contains("<set>"),
            "Debug must indicate v2 is set: {dbg}"
        );
        assert!(
            dbg.contains("<unset>"),
            "Debug must indicate v1 is unset: {dbg}"
        );
        // The byte pattern must NOT appear (in any format —
        // decimal, hex, comma-separated array form).
        assert!(
            !dbg.contains("171"),
            "Debug must not print decimal byte values (0xAB = 171): {dbg}"
        );
        assert!(
            !dbg.to_lowercase().contains("ab, ab"),
            "Debug must not print hex-comma byte values: {dbg}"
        );
        assert!(
            !dbg.contains("[171,"),
            "Debug must not print array-form byte values: {dbg}"
        );
    }

    /// Encrypted-toggle scenario: a daemon previously running with
    /// `matrix.encrypted=true` left v2 records on disk; a fresh
    /// daemon start with `matrix.encrypted=false` and an empty
    /// cache must surface the typed `DlqCrypto` error pointing at
    /// the toggle-back recovery path, NOT panic. Pre-fix the inner
    /// decode `expect`-panicked here.
    #[test]
    fn test_decode_v2_envelope_under_plaintext_config_returns_typed_error() {
        // Synthesize a v2 envelope (we don't need real AEAD here,
        // just the envelope shape that triggers the inner's
        // version-dispatch).
        let envelope = MatrixEncryptedInboundDlqRecord {
            version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
            nonce: URL_SAFE_NO_PAD.encode([0u8; crate::crypto::AEAD_NONCE_LEN]),
            ciphertext: URL_SAFE_NO_PAD.encode(b"ciphertext-stub"),
        };
        let line = serde_json::to_string(&envelope).expect("serialize envelope");

        // Empty cache + plaintext config = no key derivable. The
        // inner must return the typed error rather than panic.
        let plaintext = matrix_test_config(false);
        let err = decode_matrix_inbound_dlq_record(
            std::path::Path::new("/nonexistent"),
            &plaintext,
            &line,
        )
        .expect_err("plaintext config + v2 envelope must surface typed error");
        let msg = err.to_string();
        assert!(
            matches!(
                err,
                MatrixError::DlqCrypto(_) | MatrixError::MissingStoreSecret
            ),
            "expected DlqCrypto or MissingStoreSecret, got: {err:?}"
        );
        // If DlqCrypto, message must point at the toggle-back
        // recovery path so operators can act.
        if matches!(err, MatrixError::DlqCrypto(_)) {
            assert!(
                msg.contains("toggle back to true to drain"),
                "DlqCrypto must point at recovery path: {msg}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_append_matrix_inbound_dlq_uses_owner_only_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let record = matrix_test_dlq_record();

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        append_matrix_inbound_dlq(temp.path(), &config, state, &record)
            .await
            .expect("append DLQ");

        let path = matrix_inbound_dlq_path(temp.path());
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// Successful DLQ append must clear a previously sticky
    /// `inbound_dlq_durability_error`. The pre-fix behavior pinned the
    /// channel in Error for the daemon's lifetime after a single
    /// transient append failure even though every later append
    /// succeeded.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_durability_error_clears_on_successful_append() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let record = matrix_test_dlq_record();

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());
        assert!(state.read().inbound_durability_error_is_sticky());

        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append DLQ");

        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "successful append must clear sticky durability error"
        );
    }

    /// Pin the at-cap latch short-circuit: when
    /// `inbound_dlq_at_cap_since_ms` is fresh (less than 10s ago), an
    /// append MUST fail-fast with the "latched" failure-mode message
    /// without touching the on-disk DLQ. The latch was added so a
    /// sustained inbound-failure flood doesn't pay a full
    /// read_to_string per record after the cap has already been
    /// confirmed; this test pins that contract.
    #[tokio::test(flavor = "current_thread")]
    async fn test_append_matrix_inbound_dlq_short_circuits_when_latch_fresh() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let record = matrix_test_dlq_record();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        state.write().inbound_dlq_at_cap_since_ms = Some(now_millis());
        let err = append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect_err("fresh latch must short-circuit append");
        assert!(
            matches!(err, MatrixError::DlqCapSaturation(ref msg) if msg.contains("latched")),
            "latched failure mode must surface as DlqCapSaturation/latched: {err:?}"
        );
        let path = matrix_inbound_dlq_path(temp.path());
        assert!(
            !path.exists(),
            "short-circuit must not touch the DLQ file when no file was present"
        );
        assert!(
            state.read().inbound_durability_error_is_sticky(),
            "short-circuit must still record the per-event drop as a durability event so the \
             operator-visible sticky-Error signal stays accurate"
        );
    }

    /// Companion to the short-circuit test: when the latch is older
    /// than the TTL (MATRIX_INBOUND_DLQ_AT_CAP_LATCH_TTL_MS = 10s),
    /// the next append falls through the pre-lock latch check and
    /// re-confirms cap from disk. Pin by making the latch ancient and
    /// running an append against an empty DLQ — the append should
    /// succeed.
    #[tokio::test(flavor = "current_thread")]
    async fn test_append_matrix_inbound_dlq_falls_through_when_latch_expired() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let record = matrix_test_dlq_record();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        let ancient = now_millis().saturating_sub(MATRIX_INBOUND_DLQ_AT_CAP_LATCH_TTL_MS + 1_000);
        state.write().inbound_dlq_at_cap_since_ms = Some(ancient);
        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("expired latch must allow append");
        let path = matrix_inbound_dlq_path(temp.path());
        assert!(
            path.exists(),
            "fall-through path must commit the append once cap is re-confirmed below limit"
        );
    }

    /// Replay of an empty/missing DLQ must clear a sticky durability
    /// error, matching the append decay path.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_durability_error_clears_on_empty_replay() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());
        assert!(state.read().inbound_durability_error_is_sticky());

        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect("empty replay");
        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "empty replay tick must decay sticky durability error"
        );
    }

    /// A DLQ record whose persisted `eventId` is empty must still be
    /// rejected, while non-empty Matrix-shaped IDs with control /
    /// display-hostile bytes are preserved and replayed with a
    /// hash-derived idempotency key.
    #[test]
    fn test_decode_matrix_inbound_dlq_record_rejects_empty_event_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        // Plaintext encoding so the line is human-readable and we
        // can hand-craft an "empty event_id" record.
        let line = serde_json::json!({
            "eventId": "",
            "roomId": "!room:example.com",
            "senderId": "@alice:example.com",
            "text": "hello",
            "receivedAt": 1_700_000_000_000_i64,
        })
        .to_string();
        let err = decode_matrix_inbound_dlq_record(temp.path(), &config, &line)
            .expect_err("empty event_id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("parse Matrix inbound DLQ record"),
            "expected typed DLQ parse error, got {msg}"
        );

        let line = serde_json::json!({
            "eventId": "$abc\u{0007}def:example.com",
            "roomId": "!room:example.com",
            "senderId": "@alice:example.com",
            "text": "hello",
            "receivedAt": 1_700_000_000_000_i64,
        })
        .to_string();
        let record = decode_matrix_inbound_dlq_record(temp.path(), &config, &line)
            .expect("control-byte event_id should decode for hash-idempotent replay");
        let key = matrix_event_idempotency_key(record.event_id.as_str()).expect("hash key");
        assert!(key.as_str().starts_with("matrix-event-v3-sha256:"));
    }

    /// A line that fails to decode must NOT be silently dropped on
    /// the next replay. The current implementation moves corrupt
    /// lines to an `inbound_dlq.corrupt.jsonl` quarantine sibling so
    /// the live DLQ can drain (otherwise every replay tick
    /// re-classifies the same lines as Corrupt and the channel stays
    /// sticky-Error). Both invariants are pinned here:
    /// (a) the corrupt line is preserved verbatim in quarantine,
    /// (b) the live DLQ no longer contains it after replay.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_keeps_corrupt_lines_verbatim() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let path = matrix_inbound_dlq_path(temp.path());
        let quarantine_path = matrix_inbound_dlq_quarantine_path(temp.path());
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.expect("dir");
        }
        // Pre-seed with a line that won't decode (truncated JSON).
        let corrupt_line = "{\"eventId\":\"$abc:example.com\",  // truncated\n";
        tokio::fs::write(&path, corrupt_line)
            .await
            .expect("seed corrupt DLQ");

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect_err("corrupt-only replay must surface error");
        assert!(
            matches!(err, MatrixError::DlqSerialization(_)),
            "corrupt JSON replay must surface dlq-serialization, got {err:?}"
        );
        assert!(format!("{err}").contains("undecodable"));

        // (a) The corrupt line must be preserved verbatim in the
        // quarantine file for forensic recovery.
        let quarantined = tokio::fs::read_to_string(&quarantine_path)
            .await
            .expect("read quarantine");
        assert!(
            quarantined.contains("$abc:example.com"),
            "corrupt DLQ line must be quarantined verbatim, got {quarantined:?}"
        );

        // (b) The live DLQ must no longer contain the corrupt line —
        // either the file was rewritten empty (then deleted, hence
        // NotFound), or it exists but contains no records.
        match tokio::fs::read_to_string(&path).await {
            Ok(live) => assert!(
                !live.contains("$abc:example.com"),
                "corrupt line must be removed from live DLQ after quarantine, got {live:?}"
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("unexpected live DLQ read error: {err}"),
        }
    }

    /// Non-ruma-shaped persisted identifiers are an intentional typed-boundary
    /// narrowing: they are not replayable Matrix events, but the original line
    /// must still move to quarantine rather than disappear.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_quarantines_non_ruma_shaped_event_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let path = matrix_inbound_dlq_path(temp.path());
        let quarantine_path = matrix_inbound_dlq_quarantine_path(temp.path());
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.expect("dir");
        }
        let line = serde_json::json!({
            "eventId": "abc123",
            "roomId": "!room:example.com",
            "senderId": "@alice:example.com",
            "text": "hello",
            "receivedAt": 1_700_000_000_000_i64,
        })
        .to_string();
        tokio::fs::write(&path, format!("{line}\n"))
            .await
            .expect("seed non-ruma-shaped DLQ line");

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state)
            .await
            .expect_err("non-ruma-shaped event id must be quarantined");
        assert!(
            matches!(err, MatrixError::DlqSerialization(_)),
            "invalid persisted Matrix identifiers must surface dlq-serialization, got {err:?}"
        );
        assert!(format!("{err}").contains("undecodable"));

        let quarantined = tokio::fs::read_to_string(&quarantine_path)
            .await
            .expect("read quarantine");
        assert!(
            quarantined.contains("\"eventId\":\"abc123\""),
            "non-ruma-shaped DLQ line must be quarantined verbatim, got {quarantined:?}"
        );
        match tokio::fs::read_to_string(&path).await {
            Ok(live) => assert!(
                !live.contains("abc123"),
                "non-ruma-shaped line must be removed from live DLQ after quarantine, got {live:?}"
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("unexpected live DLQ read error: {err}"),
        }
    }

    /// DLQ replay-success path: a record that dispatches successfully
    /// must result in the file being removed by `rewrite_matrix_inbound_dlq`
    /// AND the inbound-failure streak reset on the runtime state.
    /// Pins the item-93 promised "successful deletion" + "counter
    /// reset" behaviors. Installs a real session store and activity
    /// service so dispatch reaches the "no-LLM-provider → Ok" path
    /// that legitimately produces a successful drain — without that
    /// setup the test would short-circuit through the not-found branch
    /// and never exercise the rewrite path.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_drains_succeeding_record_and_resets_inbound_streak() {
        use crate::channels::activity::ActivityService;
        use crate::server::ws::WsServerConfig;
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        // Real WsServerState wired with a tempdir-backed session store
        // and activity service so dispatch_inbound_text_with_options
        // reaches its non-failing terminal branch (no LLM provider →
        // returns Ok with run_spawned=false). Without these, dispatch
        // panics on `state.session_store()`.
        let cfg = serde_json::json!({});
        crate::config::clear_cache();
        crate::config::update_cache(cfg.clone(), cfg.clone());
        let session_dir = tempfile::tempdir().expect("session tempdir");
        let session_store = Arc::new(crate::sessions::SessionStore::with_base_path(
            session_dir.path().to_path_buf(),
        ));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let ws_state = Arc::new(
            crate::server::ws::WsServerState::new(WsServerConfig::default())
                .with_session_store(session_store)
                .with_activity_service(activity_service),
        );

        // Drive the inbound streak to a non-zero count and seed a
        // sticky durability error so the test can observe both
        // recoveries.
        state.write().record_inbound_failure();
        state.write().record_inbound_failure();
        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());

        let record = matrix_test_dlq_record();
        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append DLQ");
        let path = matrix_inbound_dlq_path(temp.path());
        assert!(path.exists(), "DLQ file present before replay");

        replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect("replay must succeed when dispatch returns Ok");

        // Real drain by `rewrite_matrix_inbound_dlq`: the file must
        // be REMOVED, not just rewritten empty.
        assert!(
            !path.exists(),
            "successfully-replayed DLQ must be drained by rewrite_matrix_inbound_dlq"
        );
        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "successful drain must clear the sticky durability error"
        );
        assert!(
            !state.read().inbound_streak_is_sticky(),
            "successful dispatch must reset the inbound failure streak"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_decodes_encrypted_record_through_fake_dispatcher() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let record = matrix_test_dlq_record();
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().expect("DLQ parent")).expect("create DLQ parent");
        let line =
            encode_matrix_inbound_dlq_record(temp.path(), &config, &record).expect("encode DLQ");
        assert!(
            line.contains("\"version\":2"),
            "encrypted replay fixture must use the current v2 DLQ envelope"
        );
        std::fs::write(&path, format!("{line}\n")).expect("write DLQ line");

        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());
        assert!(
            state.read().inbound_durability_error_is_sticky(),
            "test precondition: fake-dispatched replay must clear a planted durability error"
        );

        let dispatcher = RecordingDlqDispatcher::default();
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        replay_matrix_inbound_dlq_with_dispatcher(
            temp.path(),
            &config,
            ws_state,
            state.clone(),
            &dispatcher,
        )
        .await
        .expect("encrypted DLQ replay must dispatch successfully");

        assert_eq!(
            dispatcher.records(),
            vec![record],
            "fake dispatcher must see the decoded plaintext record from the encrypted on-disk line"
        );
        assert!(
            !path.exists(),
            "successful fake-dispatched replay must drain the encrypted DLQ file"
        );
        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "successful fake-dispatched replay must leave no sticky durability error"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_fake_dispatch_failure_retains_decoded_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let record = matrix_test_dlq_record();
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().expect("DLQ parent")).expect("create DLQ parent");
        let line =
            encode_matrix_inbound_dlq_record(temp.path(), &config, &record).expect("encode DLQ");
        std::fs::write(&path, format!("{line}\n")).expect("write DLQ line");

        let dispatcher = RecordingDlqDispatcher::failing();
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq_with_dispatcher(
            temp.path(),
            &config,
            ws_state,
            state,
            &dispatcher,
        )
        .await
        .expect_err("scripted dispatch failure must keep the record retryable");

        assert!(
            matches!(err, MatrixError::DlqDispatchFailure(_)),
            "dispatch-failed replay must surface dlq-dispatch-failure, got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("Matrix inbound DLQ replay still has 1 undelivered"),
            "dispatch failure must propagate the replay-retention summary: {err}"
        );
        assert_eq!(
            dispatcher.records(),
            vec![record],
            "fake dispatcher must receive the decoded record before replay retains it"
        );
        assert!(
            path.exists(),
            "dispatch-failed encrypted record must remain on disk for the next replay tick"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_dispatch_failure_class_wins_over_temporarily_undecodable_retention() {
        let temp = tempfile::tempdir().expect("tempdir");
        let encrypted_config = matrix_test_config(true);
        let plain_config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let mut retained_record = matrix_test_dlq_record();
        retained_record.event_id = "$retained:example.com".to_string();
        let mut dispatch_record = matrix_test_dlq_record();
        dispatch_record.event_id = "$dispatch:example.com".to_string();
        dispatch_record.text = "dispatch me after retained crypto line".to_string();
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().expect("DLQ parent")).expect("create DLQ parent");
        let retained_line =
            encode_matrix_inbound_dlq_record(temp.path(), &encrypted_config, &retained_record)
                .expect("encode encrypted retained DLQ line");
        let dispatch_line =
            encode_matrix_inbound_dlq_record(temp.path(), &plain_config, &dispatch_record)
                .expect("encode plaintext dispatch DLQ line");
        std::fs::write(&path, format!("{retained_line}\n{dispatch_line}\n"))
            .expect("write mixed DLQ lines");

        let dispatcher = RecordingDlqDispatcher::failing();
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq_with_dispatcher(
            temp.path(),
            &plain_config,
            ws_state,
            state,
            &dispatcher,
        )
        .await
        .expect_err("mixed retained+dispatch replay must report the active dispatch failure");

        assert!(
            matches!(err, MatrixError::DlqDispatchFailure(_)),
            "temporarily-undecodable retained records must not override active dispatch failure class: {err:?}"
        );
        assert!(
            err.to_string().contains("temporarily undecodable"),
            "aggregate detail must still mention retained crypto/config records: {err}"
        );
        assert_eq!(
            dispatcher.records(),
            vec![dispatch_record],
            "dispatcher must only receive the decodable plaintext record"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_retained_crypto_outranks_active_legacy_refusal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let encrypted_config = matrix_test_config(true);
        let mut plain_config = matrix_test_config(false);
        plain_config.legacy_dlq_envelope_policy = MatrixLegacyDlqEnvelopePolicy::Refuse;
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let mut retained_record = matrix_test_dlq_record();
        retained_record.event_id = "$retained:example.com".to_string();
        let mut refused_record = matrix_test_dlq_record();
        refused_record.event_id = "$legacy-refused:example.com".to_string();
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().expect("DLQ parent")).expect("create DLQ parent");
        let retained_line =
            encode_matrix_inbound_dlq_record(temp.path(), &encrypted_config, &retained_record)
                .expect("encode encrypted retained DLQ line");
        let refused_line = encode_legacy_v1_matrix_inbound_dlq_record_for_test(
            temp.path(),
            &encrypted_config,
            &refused_record,
        );
        std::fs::write(&path, format!("{refused_line}\n{retained_line}\n"))
            .expect("write mixed refused+retained DLQ lines");

        let dispatcher = RecordingDlqDispatcher::default();
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq_with_dispatcher(
            temp.path(),
            &plain_config,
            ws_state,
            state,
            &dispatcher,
        )
        .await
        .expect_err("retained crypto records must outrank active legacy refusal");

        assert!(
            matches!(
                err,
                MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable { .. })
            ),
            "retained crypto/config records must preserve their machine-readable subtype when they outrank legacy policy refusal: {err:?}"
        );
        assert!(
            is_temporarily_undecodable_dlq_error(&err),
            "aggregate retained crypto/config error must remain machine-readable as temporarily recoverable"
        );
        assert!(
            err.to_string().contains("temporarily undecodable"),
            "aggregate detail must still mention retained crypto/config records: {err}"
        );
        assert!(
            dispatcher.records().is_empty(),
            "undecodable legacy/refused records and retained crypto records must not reach dispatch"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_temporarily_undecodable_only_uses_retained_error_class() {
        let temp = tempfile::tempdir().expect("tempdir");
        let encrypted_config = matrix_test_config(true);
        let plain_config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let retained_record = matrix_test_dlq_record();
        let path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(path.parent().expect("DLQ parent")).expect("create DLQ parent");
        let retained_line =
            encode_matrix_inbound_dlq_record(temp.path(), &encrypted_config, &retained_record)
                .expect("encode encrypted retained DLQ line");
        std::fs::write(&path, format!("{retained_line}\n")).expect("write retained-only DLQ line");

        let dispatcher = RecordingDlqDispatcher::default();
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq_with_dispatcher(
            temp.path(),
            &plain_config,
            ws_state,
            state,
            &dispatcher,
        )
        .await
        .expect_err("retained-only temporarily undecodable replay must surface its retained class");

        assert!(
            matches!(
                err,
                MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable { .. })
            ),
            "retained-only temporarily undecodable records must preserve the config-unavailable subtype, got {err:?}"
        );
        assert!(
            is_temporarily_undecodable_dlq_error(&err),
            "retained-only aggregate must remain machine-readable as temporarily recoverable"
        );
        let message = err.to_string();
        assert!(
            message.starts_with("Matrix inbound DLQ crypto operation failed: encrypted v2 DLQ record encountered"),
            "config-unavailable remediation must lead the replay context so truncated operator surfaces still show the action: {message}"
        );
        assert!(
            message.contains("temporarily undecodable"),
            "aggregate detail must mention the retained crypto/config record: {err}"
        );
        assert!(
            dispatcher.records().is_empty(),
            "temporarily undecodable records must not reach the dispatcher"
        );
        assert!(
            path.exists(),
            "temporarily undecodable encrypted record must remain in the live DLQ"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_quarantines_session_history_corruption() {
        use crate::channels::activity::ActivityService;
        use crate::server::ws::WsServerConfig;
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let cfg = serde_json::json!({});
        crate::config::clear_cache();
        crate::config::update_cache(cfg.clone(), cfg.clone());
        let session_dir = tempfile::tempdir().expect("session tempdir");
        let session_store = Arc::new(crate::sessions::SessionStore::with_base_path(
            session_dir.path().to_path_buf(),
        ));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let ws_state = Arc::new(
            crate::server::ws::WsServerState::new(WsServerConfig::default())
                .with_session_store(session_store.clone())
                .with_activity_service(activity_service),
        );

        let session = session_store
            .get_or_create_session(
                "matrix:!room:example.com",
                crate::sessions::SessionMetadata {
                    channel: Some(MATRIX_CHANNEL_ID.to_string()),
                    chat_id: Some("!room:example.com".to_string()),
                    ..Default::default()
                },
            )
            .expect("create Matrix session");
        session_store
            .append_message(crate::sessions::ChatMessage::user(
                session.id.clone(),
                "seed",
            ))
            .expect("seed history");
        let history_path = session_dir.path().join(format!("{}.jsonl", session.id));
        use std::io::Write as _;
        let mut history = std::fs::OpenOptions::new()
            .append(true)
            .open(&history_path)
            .expect("open history");
        history.write_all(b"{not-json\n").expect("corrupt history");
        history.sync_all().expect("sync corrupt history");

        let record = matrix_test_dlq_record();
        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append DLQ");
        let dlq_path = matrix_inbound_dlq_path(temp.path());
        let err = replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect_err("session-history corruption should be reported after quarantine");

        assert!(
            err.to_string().contains("session-history corruption"),
            "expected typed session-history corruption in replay error, got {err}"
        );
        assert!(
            !dlq_path.exists(),
            "permanent session-history corruption should not be retried forever in live DLQ"
        );
        let quarantined =
            tokio::fs::read_to_string(matrix_inbound_dlq_quarantine_path(temp.path()))
                .await
                .expect("read quarantine");
        assert!(
            quarantined.contains(&record.event_id.to_string()),
            "quarantine should retain the raw DLQ record for operator repair"
        );
    }

    /// Batch 92: when the quarantine file is at cap and new corrupt /
    /// refused-legacy lines arrive, the tracing-warn alone is easy to
    /// lose under flood conditions. A durable audit event must fire so
    /// the operator's explicit policy decision (which routed the records
    /// to quarantine in the first place) does not silently lose records
    /// without a grep-able audit trail.
    #[tokio::test]
    async fn test_quarantine_cap_drop_emits_durable_audit_event() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let quarantine_path = matrix_inbound_dlq_quarantine_path(state_dir);
        tokio::fs::create_dir_all(quarantine_path.parent().unwrap())
            .await
            .expect("mkdir matrix");

        // Pre-fill the quarantine to AT the cap so even one small line
        // pushes it over.
        let filler = vec![b'x'; MATRIX_DLQ_QUARANTINE_MAX_BYTES as usize];
        tokio::fs::write(&quarantine_path, &filler)
            .await
            .expect("seed quarantine to cap");

        let new_lines = vec!["{\"event_id\":\"$cap-drop\"}".to_string()];
        let result = append_matrix_inbound_dlq_quarantine(state_dir, &new_lines).await;
        assert!(
            result.is_ok(),
            "cap-drop path must return Ok after durable audit succeeds: {result:?}"
        );

        // Quarantine bytes unchanged — drop was honored.
        let final_bytes = tokio::fs::read(&quarantine_path)
            .await
            .expect("read quarantine after cap-drop");
        assert_eq!(
            final_bytes, filler,
            "quarantine must not have grown past the cap"
        );

        // Audit log must contain the durable cap-drop record.
        let audit_path = state_dir.join("audit.jsonl");
        let audit_contents = tokio::fs::read_to_string(&audit_path)
            .await
            .expect("audit.jsonl must exist after cap-drop");
        assert!(
            audit_contents.contains("matrix_inbound_dlq_quarantine_cap_dropped"),
            "audit log missing cap-drop event: {audit_contents}"
        );
        assert!(
            audit_contents.contains("\"dropped_lines\":1"),
            "audit event must record dropped_lines count: {audit_contents}"
        );
    }

    /// Companion to `test_quarantine_cap_drop_emits_durable_audit_event`:
    /// when the FIRST write batch already exceeds the cap (no pre-
    /// existing quarantine file), the same durable audit must fire.
    #[tokio::test]
    async fn test_quarantine_first_write_oversize_emits_durable_audit_event() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();

        // Single line larger than the cap.
        let oversize = "x".repeat(MATRIX_DLQ_QUARANTINE_MAX_BYTES as usize + 64);
        let new_lines = vec![oversize];
        let result = append_matrix_inbound_dlq_quarantine(state_dir, &new_lines).await;
        assert!(
            result.is_ok(),
            "first-write cap-drop must succeed after durable audit: {result:?}"
        );

        let quarantine_path = matrix_inbound_dlq_quarantine_path(state_dir);
        assert!(
            !quarantine_path.exists(),
            "first-write oversize batch must not create the quarantine file"
        );

        let audit_path = state_dir.join("audit.jsonl");
        let audit_contents = tokio::fs::read_to_string(&audit_path)
            .await
            .expect("audit.jsonl must exist after first-write cap-drop");
        assert!(
            audit_contents.contains("matrix_inbound_dlq_quarantine_cap_dropped"),
            "audit log missing first-write cap-drop event: {audit_contents}"
        );
        assert!(
            audit_contents.contains("\"existing_quarantine_bytes\":0"),
            "first-write event must record existing_quarantine_bytes=0: {audit_contents}"
        );
    }

    /// Pin Batch 66: DLQ replay re-checks the sender allowlist against
    /// the current config (boot snapshot), not the snapshot at append
    /// time. An operator who removed a peer from `matrix.autoJoin`
    /// between the original receive and the next replay tick must see
    /// the queued message dropped rather than dispatched.
    #[tokio::test]
    async fn test_dlq_replay_drops_record_when_sender_no_longer_allowed() {
        use crate::channels::activity::ActivityService;
        use crate::server::ws::WsServerConfig;
        let temp = tempfile::tempdir().expect("tempdir");
        // Config WITHOUT the test sender — simulates an operator who
        // removed `@alice:example.com` from auto_join after the DLQ
        // record was originally appended.
        let mut config = matrix_test_config(false);
        config.auto_join = MatrixAutoJoinConfig::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let cfg = serde_json::json!({});
        crate::config::clear_cache();
        crate::config::update_cache(cfg.clone(), cfg.clone());
        let session_dir = tempfile::tempdir().expect("session tempdir");
        let session_store = Arc::new(crate::sessions::SessionStore::with_base_path(
            session_dir.path().to_path_buf(),
        ));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let ws_state = Arc::new(
            crate::server::ws::WsServerState::new(WsServerConfig::default())
                .with_session_store(session_store.clone())
                .with_activity_service(activity_service),
        );

        let record = matrix_test_dlq_record();
        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append DLQ");
        let dlq_path = matrix_inbound_dlq_path(temp.path());
        assert!(
            dlq_path.exists(),
            "DLQ record should exist on disk before replay"
        );

        replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect("replay must succeed: dropped records are not errors");

        assert!(
            !dlq_path.exists(),
            "DLQ file must be removed (or empty) — the now-disallowed record was dropped, \
             not left as un-dispatchable backlog occupying the cap"
        );
    }

    /// Wave-decode helper: cap-clamp truncation must classify
    /// each tail record as either decoded (collect event_id) or
    /// undecodable (count toward decode_failures). Real-cap
    /// (10000 records) is impractical in tests; helper extraction
    /// lets us pin the accounting on a small fixture.
    #[test]
    fn test_collect_dropped_event_ids_classifies_decoded_vs_undecodable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);

        // Three real records (all v2 / Argon2id) + two undecodable
        // lines (random JSON envelopes — wrong ciphertext).
        let real_records: Vec<MatrixInboundDlqRecord> = (0..3)
            .map(|i| MatrixInboundDlqRecord {
                event_id: format!("$evt-{i}:example.com"),
                room_id: "!room:example.com".to_string(),
                sender_id: "@alice:example.com".to_string(),
                text: format!("body {i}"),
                received_at: 1_700_000_000_000 + i as i64,
            })
            .collect();
        let real_lines: Vec<String> = real_records
            .iter()
            .map(|r| {
                encode_matrix_inbound_dlq_record(temp.path(), &config, r)
                    .expect("encode real record")
            })
            .collect();
        // Synthesize an envelope-shaped line with garbage
        // ciphertext — decodes to AEAD failure.
        let garbage_line = serde_json::to_string(&MatrixEncryptedInboundDlqRecord {
            version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
            nonce: URL_SAFE_NO_PAD.encode([0u8; crate::crypto::AEAD_NONCE_LEN]),
            ciphertext: URL_SAFE_NO_PAD.encode(b"random-junk-not-real-ciphertext"),
        })
        .expect("serialize");
        let mut tail = real_lines.clone();
        tail.push(garbage_line.clone());
        tail.push(garbage_line);

        let keys = MatrixDlqKeys::empty();
        keys.ensure_v2(temp.path(), &config).expect("derive v2");
        let (dropped_ids, decode_failures) =
            collect_dropped_event_ids_from_tail(&tail, Some(&keys));

        assert_eq!(
            decode_failures, 2,
            "garbage envelopes must surface as decode_failures"
        );
        assert_eq!(
            dropped_ids,
            vec![
                "$evt-0:example.com".to_string(),
                "$evt-1:example.com".to_string(),
                "$evt-2:example.com".to_string(),
            ],
            "decoded event_ids preserved in tail order"
        );
    }

    /// Pinned vector for the inbound-DLQ HKDF derivation. Drift here
    /// is a silent wire-format break: an operator upgrading carapace
    /// while a non-empty `inbound_dlq.jsonl` is on disk would lose
    /// access to those records (decryption would yield gibberish or
    /// AEAD-tag failures, and the records would land in the
    /// quarantine sibling). Pin against a known input so any rotation
    /// of `MATRIX_INBOUND_DLQ_INFO`, salt formula, or HKDF-construction
    /// detail trips this test before shipping.
    #[test]
    fn test_pinned_matrix_inbound_dlq_key_vector() {
        let key = derive_matrix_inbound_dlq_key_from(
            b"correct horse battery staple",
            b"installation-00000000-0000-0000-0000-000000000000",
        )
        .unwrap();
        assert_eq!(
            hex::encode(key),
            "4f17d4dc2615c81e3e552fe15374de09634d883e4b7835a1d43a04676f5a0ff7"
        );
    }

    #[test]
    fn test_pinned_matrix_inbound_dlq_v2_key_vector() {
        // Inputs are intentional pinned test fixtures — see v1 vector above.
        // Routed through `Vec` rather than literal byte slices so static
        // analysis doesn't misread the pin as a real password/salt.
        let passphrase: Vec<u8> = Vec::from(&b"correct horse battery staple"[..]);
        let installation: Vec<u8> =
            Vec::from(&b"installation-00000000-0000-0000-0000-000000000000"[..]);
        let key =
            derive_matrix_inbound_dlq_key_v2_from(passphrase.as_slice(), installation.as_slice())
                .unwrap();
        assert_eq!(
            hex::encode(key),
            "92a4336c637a2792d43ce389686fb958777d557c27a79c287bac9d8350b12c78"
        );
    }

    /// v2 derivation (Argon2id) must be deterministic over
    /// `(passphrase, installation_id)` so that the encode-time and
    /// decode-time keys match across daemon restarts. A pinned
    /// expected hex value would be fragile against future Argon2id
    /// parameter rotations (memory / iterations / lanes), which are
    /// signaled by an envelope-version bump rather than a derivation
    /// drift, so this test asserts the determinism property
    /// directly: the same inputs produce byte-identical keys, and a
    /// different input produces a different key.
    #[test]
    fn test_v2_argon2id_derivation_is_deterministic() {
        // Generate non-secret fixtures at test time so this test
        // doesn't carry hardcoded byte literals into a derivation
        // function — CodeQL flags hardcoded inputs into crypto
        // APIs as a code-smell. The determinism property holds
        // regardless of the specific bytes; we only need
        // (passphrase, salt) inputs that round-trip stably and
        // a second pair that differs in passphrase or salt.
        let mut passphrase = [0u8; 32];
        let mut salt = [0u8; 32];
        getrandom::fill(&mut passphrase).expect("getrandom passphrase");
        getrandom::fill(&mut salt).expect("getrandom salt");

        let key_a = derive_matrix_inbound_dlq_key_v2_from(&passphrase, &salt).expect("v2 derive a");
        let key_b = derive_matrix_inbound_dlq_key_v2_from(&passphrase, &salt).expect("v2 derive b");
        assert_eq!(*key_a, *key_b, "Argon2id derivation must be deterministic");

        let mut other_passphrase = [0u8; 32];
        getrandom::fill(&mut other_passphrase).expect("getrandom other passphrase");
        let key_c =
            derive_matrix_inbound_dlq_key_v2_from(&other_passphrase, &salt).expect("v2 derive c");
        assert_ne!(
            *key_a, *key_c,
            "Argon2id keys must differ for different passphrases"
        );

        let mut other_salt = [0u8; 32];
        getrandom::fill(&mut other_salt).expect("getrandom other salt");
        let key_d =
            derive_matrix_inbound_dlq_key_v2_from(&passphrase, &other_salt).expect("v2 derive d");
        assert_ne!(
            *key_a, *key_d,
            "Argon2id keys must differ for different installation_ids"
        );

        // v1 (HKDF) and v2 (Argon2id) MUST produce different keys
        // for the same inputs — sharing a derivation would defeat
        // the dual-version envelope (a v1 reader could decode v2
        // ciphertext or vice versa).
        let v1 = derive_matrix_inbound_dlq_key_v1_from(&passphrase, &salt).expect("v1 derive");
        assert_ne!(
            *key_a, *v1,
            "v1 (HKDF) and v2 (Argon2id) must derive distinct keys for the same inputs"
        );
    }

    /// `MatrixDlqKeys::ensure_v2` must cache the derivation result.
    /// A second call with the same inputs returns the SAME borrowed
    /// reference (pointer-equal). A future refactor that always
    /// re-derives (e.g. drops the OnceLock fast-path) would silently
    /// regress to ~100ms per call, defeating the daemon-lifetime
    /// cache. The byte-equality check would still pass under that
    /// regression, but pointer equality cannot.
    #[test]
    fn test_matrix_dlq_keys_ensure_v2_cache_idempotence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let keys = MatrixDlqKeys::empty();
        let first = keys.ensure_v2(temp.path(), &config).expect("v2 derive");
        // Capture the pointer of the first borrow; immediately
        // release the borrow so we can re-call.
        let first_ptr = first.as_ptr();
        let second = keys
            .ensure_v2(temp.path(), &config)
            .expect("v2 derive cached");
        let second_ptr = second.as_ptr();
        assert_eq!(
            first_ptr, second_ptr,
            "ensure_v2 must return the same OnceLock-backed reference \
             on a second call (cache hit); a regression that re-derives \
             would have a different pointer"
        );
    }

    /// Pin: `append_matrix_inbound_dlq` reaches the v2 key through
    /// the daemon-lifetime `MatrixDlqKeys` cache, never the
    /// standalone `derive_matrix_inbound_dlq_key_v2_from`.
    /// Bypassing the cache regresses concurrent inbound dispatch
    /// failures to a fresh ~100ms Argon2id derivation per record
    /// while holding `dlq_io_lock` — byte-equivalence pins don't
    /// catch this; only call-site routing does.
    #[test]
    fn test_append_matrix_inbound_dlq_routes_through_cache() {
        // Disambiguate from `append_matrix_inbound_dlq_quarantine`,
        // which has a different prefix-match in the source.
        let body = matrix_rs_fn_body("async fn append_matrix_inbound_dlq(");
        let body = body.as_str();

        assert!(
            body.contains("state.read().dlq_keys()"),
            "append_matrix_inbound_dlq must fetch the cache via \
             state.read().dlq_keys() — direct derivation defeats \
             the daemon-lifetime fast-path"
        );
        assert!(
            body.contains("dlq_keys.ensure_v2(state_dir, config)"),
            "append_matrix_inbound_dlq must obtain the v2 key via \
             dlq_keys.ensure_v2(state_dir, config)"
        );
        assert!(
            !body.contains("derive_matrix_inbound_dlq_key_v2_from"),
            "append_matrix_inbound_dlq must NOT call the standalone \
             derive helper directly — that path bypasses the cache"
        );
    }

    /// `MatrixDlqKeys::ensure_v2` first-derivation-failure must NOT
    /// poison the OnceLock — a subsequent successful call after the
    /// operator fixes their config must populate the slot. Otherwise
    /// transient `MissingStoreSecret` (env var unset for one call)
    /// would permanently wedge the cache for the daemon's lifetime.
    #[test]
    fn test_matrix_dlq_keys_ensure_v2_retries_after_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        // Plaintext config: ensure_v2 fails with MissingStoreSecret.
        let plain = matrix_test_config(false);
        let keys = MatrixDlqKeys::empty();
        let err = keys
            .ensure_v2(temp.path(), &plain)
            .expect_err("ensure_v2 must fail with no passphrase");
        assert!(matches!(err, MatrixError::MissingStoreSecret));
        // OnceLock must remain empty so the next call can retry.
        assert!(keys.v2().is_none(), "failure must not poison the OnceLock");

        // Re-attempt with a passphrase available — must succeed.
        let encrypted = matrix_test_config(true);
        let _ = keys
            .ensure_v2(temp.path(), &encrypted)
            .expect("ensure_v2 must succeed after config is fixed");
        assert!(keys.v2().is_some());
    }

    /// Pin: `replay_matrix_inbound_dlq` cap-clamp wires the SUFFIX
    /// (records being dropped) through `collect_dropped_event_ids_from_tail`
    /// → `record_inbound_dlq_lost_event_ids` → undecodable-count
    /// surfacing → `truncate`. End-to-end is impractical (10K
    /// records) and lowering the cap via `#[cfg(test)]` weakens
    /// the production guard. The two failure modes this catches:
    /// inverting the slice index (KEPT prefix vs DROPPED suffix)
    /// and ordering the truncate before the tail-decode (suffix
    /// becomes empty before decoding).
    #[test]
    fn test_replay_matrix_inbound_dlq_cap_clamp_wiring_pinned() {
        let body = matrix_rs_fn_body("async fn replay_matrix_inbound_dlq_with_dispatcher");
        let body = body.as_str();

        // The tail must be sliced from the cap (not to it). A
        // `..MATRIX_INBOUND_DLQ_MAX_RECORDS` slice would describe
        // the KEPT prefix, not the dropped suffix — silently
        // logging the wrong event IDs.
        assert!(
            body.contains("merged_lines[MATRIX_INBOUND_DLQ_MAX_RECORDS..]"),
            "cap-clamp must decode the SUFFIX (records being dropped), not \
             the prefix (records kept) — `merged_lines[MATRIX_INBOUND_DLQ_MAX_RECORDS..]`"
        );
        assert!(
            body.contains("collect_dropped_event_ids_from_tail"),
            "cap-clamp must call collect_dropped_event_ids_from_tail to \
             decode the suffix"
        );
        assert!(
            body.contains("record_inbound_dlq_lost_event_ids"),
            "cap-clamp must surface the dropped event IDs for operator \
             forensics via record_inbound_dlq_lost_event_ids"
        );
        assert!(
            body.contains("inbound_dlq_undecodable_lost_count"),
            "cap-clamp must surface undecodable-but-lost count separately \
             from event IDs (decode_failures > 0 case)"
        );
        // Truncation MUST happen after the tail decode. We pin
        // ordering by checking that `truncate(MATRIX_INBOUND_DLQ_MAX_RECORDS)`
        // appears after the call to `collect_dropped_event_ids_from_tail`
        // in source order.
        let decode_pos = body
            .find("collect_dropped_event_ids_from_tail")
            .expect("decode-call must exist");
        let truncate_pos = body
            .find("merged_lines.truncate(MATRIX_INBOUND_DLQ_MAX_RECORDS)")
            .expect("truncate-call must exist");
        assert!(
            truncate_pos > decode_pos,
            "truncate must run AFTER tail-decode; otherwise the suffix \
             being decoded is empty and dropped_ids is silently zero"
        );
    }

    /// Encryption-flag flip detection: a plaintext record (encoded
    /// when `matrix.encrypted=false`) MUST decode under a config
    /// that has since flipped to `matrix.encrypted=true`. The
    /// reverse direction (encrypted line under encrypted=false
    /// config) requires the original passphrase to decrypt, so it
    /// is ALSO a supported migration but only when the operator
    /// keeps the passphrase configured during the transition —
    /// the introspection branch correctly recognizes the line
    /// shape, but key resolution still has to succeed. This test
    /// pins the introspection logic itself: line shape governs
    /// the decode branch, NOT `config.encrypted()`.
    #[test]
    fn test_matrix_inbound_dlq_plaintext_decodes_under_encrypted_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record = matrix_test_dlq_record();
        let plain_config = matrix_test_config(false);
        let enc_config = matrix_test_config(true);

        // Encode under encrypted=false, decode under encrypted=true.
        // The plaintext line carries no version/nonce/ciphertext,
        // so the introspection branch falls into plaintext-decode
        // regardless of the config's encryption flag.
        let plain_line = encode_matrix_inbound_dlq_record(temp.path(), &plain_config, &record)
            .expect("plaintext encode");
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &enc_config, &plain_line)
            .expect("plaintext line must decode under encrypted config via introspection");
        assert_eq!(decoded, record);
    }

    #[test]
    fn test_temporarily_undecodable_encrypted_dlq_error_is_preserved() {
        assert!(is_temporarily_undecodable_dlq_error(
            &MatrixError::MissingStoreSecret
        ));
        assert!(is_temporarily_undecodable_dlq_error(
            &dlq_crypto_config_unavailable(MATRIX_INBOUND_DLQ_ENVELOPE_VERSION)
        ));
        assert!(!is_temporarily_undecodable_dlq_error(
            &MatrixError::DlqSerialization("Matrix inbound DLQ corrupt record".to_string())
        ));
        // Post-Batch-79: `LegacyDlqEnvelopeRefused` is the operator's
        // EXPLICIT policy choice and no toggle makes the records
        // decodable later, so it is NOT a temporarily-undecodable
        // class. Routing it through the Corrupt branch preserves
        // refused records in the quarantine artifact for operator
        // inspection rather than the live-DLQ tail where cap-pressure
        // would drop them.
        assert!(!is_temporarily_undecodable_dlq_error(
            &legacy_dlq_envelope_refused("refused legacy v1")
        ));
    }

    #[test]
    fn test_rotate_matrix_inbound_dlq_for_rekey_keeps_old_backup_until_cleanup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let old_config = matrix_test_config_with_passphrase(&old_passphrase);
        let new_config = matrix_test_config_with_passphrase(&new_passphrase);
        let record = matrix_test_dlq_record();
        let old_line = encode_matrix_inbound_dlq_record(temp.path(), &old_config, &record)
            .expect("old-keyed DLQ line");
        let live_path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, format!("{old_line}\n")).expect("write live DLQ");

        let outcome = rotate_matrix_inbound_dlq_for_rekey(
            temp.path(),
            &old_config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect("rekey live DLQ");

        let MatrixDlqRekeyOutcome::Rotated {
            decoded_count,
            backup_path,
        } = outcome
        else {
            panic!("non-empty DLQ must rotate");
        };
        assert_eq!(decoded_count, 1);
        assert!(
            backup_path.exists(),
            "old-keyed backup must remain until passphrase promotion succeeds"
        );
        let new_live = std::fs::read_to_string(&live_path).expect("read new live DLQ");
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &new_config, new_live.trim())
            .expect("new live DLQ must decode under new passphrase");
        assert_eq!(decoded, record);
        let old_backup = std::fs::read_to_string(&backup_path).expect("read backup DLQ");
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &old_config, old_backup.trim())
            .expect("backup DLQ must remain under old passphrase");
        assert_eq!(decoded, record);
    }

    #[test]
    fn test_rotate_matrix_inbound_dlq_for_rekey_honors_legacy_refuse_policy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let mut old_config = matrix_test_config_with_passphrase(&old_passphrase);
        old_config.legacy_dlq_envelope_policy = MatrixLegacyDlqEnvelopePolicy::Refuse;
        let record = matrix_test_dlq_record();
        let v1_line =
            encode_legacy_v1_matrix_inbound_dlq_record_for_test(temp.path(), &old_config, &record);
        let live_path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, format!("{v1_line}\n")).expect("write live DLQ");

        let err = rotate_matrix_inbound_dlq_for_rekey(
            temp.path(),
            &old_config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect_err("rekey must not launder refused v1 into v2");

        assert!(matches!(err, MatrixError::LegacyDlqEnvelopeRefused(_)));
        assert!(
            err.to_string()
                .contains("legacy Matrix inbound DLQ v1 envelope refused by policy"),
            "unexpected rekey refusal error: {err}"
        );
        assert!(
            matrix_inbound_dlq_rekey_backup_path(temp.path())
                .try_exists()
                .is_ok_and(|exists| !exists),
            "refused rekey must leave the original live file in place"
        );
    }

    #[test]
    fn test_rotate_matrix_inbound_dlq_for_rekey_preserves_decode_error_kind() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let config = matrix_test_config_with_passphrase(&old_passphrase);
        let live_path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, "{not json}\n").expect("write malformed live DLQ");

        let err = rotate_matrix_inbound_dlq_for_rekey(
            temp.path(),
            &config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect_err("malformed DLQ line must fail rekey before rewriting");

        assert!(
            matches!(err, MatrixError::DlqSerialization(_)),
            "rekey decode failures must preserve serialization kind, got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("failed to decode DLQ line under OLD passphrase"),
            "rekey wrapper must preserve operator context: {err}"
        );
        assert!(
            matrix_inbound_dlq_rekey_backup_path(temp.path())
                .try_exists()
                .is_ok_and(|exists| !exists),
            "failed decode must not create a rekey backup"
        );
    }

    #[test]
    fn test_dlq_rekey_decode_error_preserves_config_unavailable_subtype() {
        let temp = tempfile::tempdir().expect("tempdir");
        let err = dlq_rekey_decode_error(
            MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable {
                version: Some(1),
                context: None,
            }),
            temp.path(),
        );

        assert!(
            matches!(
                err,
                MatrixError::DlqCrypto(DlqCryptoFailure::ConfigUnavailable {
                    version: Some(1),
                    ..
                })
            ),
            "rekey wrapper must preserve operator-actionable DLQ crypto subtype, got {err:?}"
        );
    }

    #[test]
    fn test_rotate_matrix_inbound_dlq_for_rekey_enforces_cap_before_decode() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let config = matrix_test_config_with_passphrase(&old_passphrase);
        let live_path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        let mut content = String::new();
        for _ in 0..=MATRIX_INBOUND_DLQ_MAX_RECORDS {
            content.push_str("{}\n");
        }
        std::fs::write(&live_path, content).expect("write over-cap live DLQ");

        let err = rotate_matrix_inbound_dlq_for_rekey(
            temp.path(),
            &config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect_err("over-cap DLQ must fail before decrypting malformed records");

        assert!(
            err.to_string().contains("inbound DLQ has more than"),
            "unexpected error: {err}"
        );
    }

    /// A planted regular DLQ file passing the no-follow open check
    /// but holding one huge newline-free line used to OOM the rekey
    /// reader (unbounded `BufRead::read_line` into a String). The
    /// per-line cap mirrors the live-DLQ replay/count seam at
    /// `read_matrix_inbound_dlq_lines_streaming` and
    /// `matrix_inbound_dlq_line_count` — the rekey reader must fail
    /// closed at the same threshold, not allocate the whole line.
    #[test]
    fn test_rotate_matrix_inbound_dlq_for_rekey_enforces_per_line_cap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let config = matrix_test_config_with_passphrase(&old_passphrase);
        let live_path = matrix_inbound_dlq_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        // One huge newline-free line just over the per-line cap. No
        // terminating newline — the cap-without-newline branch fails
        // closed before any further allocation.
        let oversize = "x".repeat(MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES + 1);
        std::fs::write(&live_path, &oversize).expect("write oversize line DLQ");

        let err = rotate_matrix_inbound_dlq_for_rekey(
            temp.path(),
            &config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect_err("oversize-line DLQ must fail before allocating the full line");

        assert!(
            err.to_string().contains(&format!(
                "exceeding {MATRIX_INBOUND_DLQ_REPLAY_LINE_MAX_BYTES} bytes"
            )),
            "unexpected error (expected per-line cap message): {err}"
        );
        assert!(
            matrix_inbound_dlq_rekey_backup_path(temp.path())
                .try_exists()
                .is_ok_and(|exists| !exists),
            "refused rekey must leave the original live file in place"
        );
    }

    #[test]
    fn test_recover_matrix_inbound_dlq_rekey_restores_from_backup_when_live_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let old_config = matrix_test_config_with_passphrase(&old_passphrase);
        let new_config = matrix_test_config_with_passphrase(&new_passphrase);
        let record = matrix_test_dlq_record();
        let old_line = encode_matrix_inbound_dlq_record(temp.path(), &old_config, &record)
            .expect("old-keyed DLQ line");
        let live_path = matrix_inbound_dlq_path(temp.path());
        let backup_path = matrix_inbound_dlq_rekey_backup_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, "").expect("write empty live DLQ");
        std::fs::write(&backup_path, format!("{old_line}\n")).expect("write backup DLQ");

        let outcome = recover_matrix_inbound_dlq_rekey(
            temp.path(),
            &new_config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect("recover DLQ rekey");

        let MatrixDlqRekeyOutcome::Rotated {
            decoded_count,
            backup_path: outcome_backup,
        } = outcome
        else {
            panic!("backup-only DLQ recovery must rotate");
        };
        assert_eq!(decoded_count, 1);
        assert_eq!(outcome_backup, backup_path);
        assert!(
            backup_path.exists(),
            "backup must remain until the pending passphrase is promoted"
        );
        let new_live = std::fs::read_to_string(&live_path).expect("read recovered live DLQ");
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &new_config, new_live.trim())
            .expect("recovered live DLQ must decode under new passphrase");
        assert_eq!(decoded, record);
    }

    #[test]
    fn test_recover_matrix_inbound_dlq_rekey_honors_legacy_refuse_policy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let old_config = matrix_test_config_with_passphrase(&old_passphrase);
        let mut new_config = matrix_test_config_with_passphrase(&new_passphrase);
        new_config.legacy_dlq_envelope_policy = MatrixLegacyDlqEnvelopePolicy::Refuse;
        let record = matrix_test_dlq_record();
        let v1_line =
            encode_legacy_v1_matrix_inbound_dlq_record_for_test(temp.path(), &old_config, &record);
        let live_path = matrix_inbound_dlq_path(temp.path());
        let backup_path = matrix_inbound_dlq_rekey_backup_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, "").expect("write empty live DLQ");
        std::fs::write(&backup_path, format!("{v1_line}\n")).expect("write backup DLQ");

        let err = recover_matrix_inbound_dlq_rekey(
            temp.path(),
            &new_config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect_err("rekey recovery must not launder refused v1 into v2");

        assert!(matches!(err, MatrixError::LegacyDlqEnvelopeRefused(_)));
        assert!(
            err.to_string()
                .contains("legacy Matrix inbound DLQ v1 envelope refused by policy"),
            "unexpected rekey recovery refusal error: {err}"
        );
        assert!(
            backup_path.exists(),
            "refused recovery must keep the old backup for operator policy reversal"
        );
    }

    #[test]
    fn test_recover_matrix_inbound_dlq_rekey_keeps_rekeyed_live_when_backup_exists() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let old_config = matrix_test_config_with_passphrase(&old_passphrase);
        let new_config = matrix_test_config_with_passphrase(&new_passphrase);
        let record = matrix_test_dlq_record();
        let old_line = encode_matrix_inbound_dlq_record(temp.path(), &old_config, &record)
            .expect("old-keyed DLQ line");
        let new_line = encode_matrix_inbound_dlq_record(temp.path(), &new_config, &record)
            .expect("new-keyed DLQ line");
        let live_path = matrix_inbound_dlq_path(temp.path());
        let backup_path = matrix_inbound_dlq_rekey_backup_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, format!("{new_line}\n")).expect("write rekeyed live DLQ");
        std::fs::write(&backup_path, format!("{old_line}\n")).expect("write old backup DLQ");

        let outcome = recover_matrix_inbound_dlq_rekey(
            temp.path(),
            &new_config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect("recover DLQ rekey");

        let MatrixDlqRekeyOutcome::Rotated {
            decoded_count,
            backup_path: outcome_backup,
        } = outcome
        else {
            panic!("backup+live recovery should keep rekeyed live as rotated");
        };
        assert_eq!(decoded_count, 1);
        assert_eq!(outcome_backup, backup_path);
        assert!(
            backup_path.exists(),
            "old backup must remain until pending passphrase promotion succeeds"
        );
        let live_after = std::fs::read_to_string(&live_path).expect("read live DLQ");
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &new_config, live_after.trim())
            .expect("live DLQ must remain decodable under new passphrase");
        assert_eq!(decoded, record);
    }

    #[test]
    fn test_recover_matrix_inbound_dlq_rekey_refuses_old_keyed_live_with_backup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old_passphrase = crate::crypto::generate_hex_secret(32).expect("old passphrase");
        let new_passphrase = crate::crypto::generate_hex_secret(32).expect("new passphrase");
        let old_config = matrix_test_config_with_passphrase(&old_passphrase);
        let record = matrix_test_dlq_record();
        let old_line = encode_matrix_inbound_dlq_record(temp.path(), &old_config, &record)
            .expect("old-keyed DLQ line");
        let live_path = matrix_inbound_dlq_path(temp.path());
        let backup_path = matrix_inbound_dlq_rekey_backup_path(temp.path());
        std::fs::create_dir_all(live_path.parent().expect("DLQ parent")).expect("create parent");
        std::fs::write(&live_path, format!("{old_line}\n")).expect("write old-keyed live DLQ");
        std::fs::write(&backup_path, format!("{old_line}\n")).expect("write old backup DLQ");

        let new_config = matrix_test_config_with_passphrase(&new_passphrase);
        let err = recover_matrix_inbound_dlq_rekey(
            temp.path(),
            &new_config,
            &old_passphrase,
            &new_passphrase,
        )
        .expect_err("backup recovery must not clobber a non-empty live DLQ");

        assert!(
            err.to_string().contains("refusing to clobber"),
            "unexpected rekey recovery error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&live_path).expect("read live after refusal"),
            format!("{old_line}\n")
        );
    }
}
