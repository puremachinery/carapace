//! Matrix recovery-key lifecycle.
//!
//! This module owns cross-signing bootstrap, recovery-key restore,
//! rotation markers, and cleanup-journal recovery. It treats on-disk
//! marker files as a small state machine: every destructive cleanup path
//! must preserve enough provenance to either resume safely or fail closed.

use super::*;

fn cross_signing_bootstrap_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::CrossSigningBootstrapFailed(detail.into())
}

fn recovery_key_restore_failed(
    reason: RecoveryRestoreFailureReason,
    detail: impl Into<String>,
) -> MatrixError {
    MatrixError::RecoveryKeyRestoreFailed {
        reason,
        detail: detail.into(),
    }
}

fn recovery_state_probe_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::RecoveryStateProbeFailed(detail.into())
}

fn recovery_state_io_failed(detail: impl Into<String>) -> MatrixError {
    MatrixError::RecoveryStateIo(detail.into())
}

fn classify_recovery_restore_failure(message: &str) -> RecoveryRestoreFailureReason {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("not configured")
        || normalized.contains("no secret storage")
        || normalized.contains("secret storage is not")
        || normalized.contains("backup disabled")
    {
        RecoveryRestoreFailureReason::ServerNotConfigured
    } else if normalized.contains("unpickle") || normalized.contains("pickle") {
        RecoveryRestoreFailureReason::UnpicklingFailed
    } else if normalized.contains("decrypt")
        || normalized.contains("mac")
        || normalized.contains("key")
        || normalized.contains("passphrase")
    {
        RecoveryRestoreFailureReason::WrongKey
    } else {
        RecoveryRestoreFailureReason::TransportError
    }
}

pub(super) async fn maybe_bootstrap_cross_signing(
    client: &Client,
    config: &MatrixConfig,
    password: Option<&str>,
    state_dir: &Path,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    session: &ValidatedMatrixSession,
) -> Result<(), MatrixError> {
    if !config.encrypted() {
        return Ok(());
    }
    let Err(err) = client
        .encryption()
        .bootstrap_cross_signing_if_needed(None)
        .await
    else {
        maybe_enable_recovery(client, config, state_dir, state, session).await?;
        let user_id = sanitize_homeserver_identifier(session.user_id.as_str());
        warn!(
            audit_event = "matrix_cross_signing_bootstrapped",
            outcome = "confirmed_or_bootstrapped_without_uia",
            user_id = %user_id,
            "Matrix cross-signing bootstrap decision completed"
        );
        emit_cross_signing_bootstrapped_audit(
            state_dir,
            user_id.clone(),
            crate::logging::audit::MatrixCrossSigningBootstrapOutcome::ConfirmedOrBootstrappedWithoutUia,
        );
        return Ok(());
    };
    let Some(response) = err.as_uiaa_response() else {
        let sanitized_user_id = sanitize_homeserver_identifier(session.user_id.as_str());
        emit_cross_signing_bootstrap_failed_audit(
            state_dir,
            sanitized_user_id,
            crate::logging::audit::MatrixCrossSigningBootstrapFailureOutcome::FailedBeforeUia,
            "non-UIA error returned by homeserver to initial bootstrap".to_string(),
        );
        return Err(cross_signing_bootstrap_failed(format!(
            "cross-signing bootstrap failed before UIA: {err}"
        )));
    };
    let Some(password) = password else {
        let sanitized_user_id = sanitize_homeserver_identifier(session.user_id.as_str());
        emit_cross_signing_bootstrap_failed_audit(
            state_dir,
            sanitized_user_id,
            crate::logging::audit::MatrixCrossSigningBootstrapFailureOutcome::FailedMissingPassword,
            "UIA requested but no matrix.password / MATRIX_PASSWORD provided".to_string(),
        );
        return Err(cross_signing_bootstrap_failed(
            "cross-signing bootstrap requires password UIA; provide matrix.password or MATRIX_PASSWORD once".to_string(),
        ));
    };
    // Use the validated user_id from the witness instead of re-parsing
    // `config.user_id`. Re-reading config between validation and
    // bootstrap is a TOCTOU window where a config mutation mid-flow
    // would let bootstrap run for a different user than was just
    // validated.
    //
    // SECURITY: `password.to_string()` materializes a plain (NOT
    // Zeroizing) String that ruma's `Password` holds inline and
    // serializes into the UIA request body. The matrix-sdk / ruma API
    // does not expose a Zeroizing-capable construction path; the
    // plaintext lives on the heap for the duration of the UIA request
    // (one HTTPS round-trip + response handling) before drop. Mitigation
    // would require re-implementing the UIA serializer (out of scope).
    // Mirrors the documented leak at `persist_matrix_session_blocking`
    // (~line 5921). Window is much narrower than the access_token leak
    // above (request lifetime vs client lifetime).
    let mut auth = matrix_sdk::ruma::api::client::uiaa::Password::new(
        matrix_sdk::ruma::api::client::uiaa::UserIdentifier::UserIdOrLocalpart(
            session.user_id.to_string(),
        ),
        password.to_string(),
    );
    auth.session = response.session.clone();
    let post_uia_result = client
        .encryption()
        .bootstrap_cross_signing(Some(
            matrix_sdk::ruma::api::client::uiaa::AuthData::Password(auth),
        ))
        .await;
    if let Err(err) = post_uia_result {
        let sanitized_user_id = sanitize_homeserver_identifier(session.user_id.as_str());
        let typed = matrix_sync_terminal_error(&err);
        let error_kind = if typed.is_some() {
            "homeserver terminal-class error after UIA (likely auth token revoked)".to_string()
        } else {
            "homeserver non-terminal error after UIA".to_string()
        };
        emit_cross_signing_bootstrap_failed_audit(
            state_dir,
            sanitized_user_id,
            crate::logging::audit::MatrixCrossSigningBootstrapFailureOutcome::FailedAfterUia,
            error_kind,
        );
        return Err(match typed {
            // The post-UIA bootstrap call still hits the homeserver,
            // and a homeserver that revokes / locks the account
            // between password verification and bootstrap returns a
            // typed terminal class. Preserve the typed
            // `AuthTokenRevoked` so the operator-facing rekey hint
            // routes through `verify_matrix_outcome`'s typed arm.
            Some(typed) => typed,
            None => cross_signing_bootstrap_failed(format!(
                "cross-signing bootstrap failed after UIA: {err}"
            )),
        });
    }
    maybe_enable_recovery(client, config, state_dir, state, session).await?;
    let user_id = sanitize_homeserver_identifier(session.user_id.as_str());
    warn!(
        audit_event = "matrix_cross_signing_bootstrapped",
        outcome = "bootstrapped_after_uia",
        user_id = %user_id,
        "Matrix cross-signing bootstrap completed after password UIA"
    );
    emit_cross_signing_bootstrapped_audit(
        state_dir,
        user_id.clone(),
        crate::logging::audit::MatrixCrossSigningBootstrapOutcome::BootstrappedAfterUia,
    );
    // SECURITY (B132): UIA consumed the operator-supplied password
    // to authorize cross-signing key creation. The token-restore
    // arm of the parent `build_matrix_client` does NOT wipe
    // `matrix.password` post-restore (unlike the password-login
    // arm which does so right after persist_matrix_session). If
    // the operator hand-edited config to set
    // `accessToken+deviceId` while leaving `password` for the
    // bootstrap-UIA, the password would sit in config
    // indefinitely after this point — exactly the surface B111
    // and B114 fought to keep narrow.
    //
    // Wipe the password here, on the AFTER-UIA branch only. The
    // ConfirmedOrBootstrappedWithoutUia branch above leaves the
    // password in place because we didn't actually use it this
    // run, and a future recurrence (homeserver invalidated
    // cross-signing keys after a security incident) would need
    // it for the next UIA. The password just consumed at line
    // 4504-4509 is logically "spent"; remove it from disk now
    // so a subsequent operator audit doesn't find a stale
    // plaintext-or-enc:v2 password lingering in config.
    if let Err(err) = remove_persisted_matrix_password().await {
        // Non-fatal: cross-signing is in place; the password
        // residue is a hygiene issue, not an availability one.
        // Operator-visible warn so the residue is noticed.
        tracing::warn!(
            error = %err,
            "Matrix cross-signing bootstrap succeeded but failed to wipe the now-redundant \
             matrix.password from config; operator should remove it manually so future audits \
             don't flag a stale secret"
        );
    }
    Ok(())
}

pub(super) async fn maybe_restore_recovery_key(
    client: &Client,
    config: &MatrixConfig,
    state_dir: &Path,
    _session: &ValidatedMatrixSession,
) -> Result<(), MatrixError> {
    // The witness is required to call this function — its presence in
    // the signature is what gates recovery-key restore behind a
    // validated session. The body itself doesn't read the witness's
    // user_id/device_id because the `recover` SDK call doesn't take
    // them; the type-level guard is the entire point.
    if !config.encrypted() {
        return Ok(());
    }
    let path = matrix_recovery_key_path(state_dir);
    // Wrap the raw file read in Zeroizing BEFORE any further processing
    // so the un-trimmed source allocation (which may include trailing
    // newline / whitespace bytes that are NOT in the trimmed slice) is
    // wiped on drop. A plain String would leave the recovery-key bytes
    // in heap memory until the allocator reclaims them — long enough on
    // a daemon-startup path to be observable in a coredump.
    let Some(recovery_key_raw) =
        read_recovery_key_file_to_string_bounded(&path, "Matrix recovery key").await?
    else {
        return Ok(());
    };
    let recovery_key = recovery_key_raw.trim();
    if recovery_key.is_empty() {
        return Err(recovery_key_restore_failed(
            RecoveryRestoreFailureReason::WrongKey,
            format!("Matrix recovery key file {} is empty", path.display()),
        ));
    }

    // SECURITY: SDK boundary leak — carapace side passes a borrowed
    // `&str` from the `Zeroizing` recovery-key allocation, but matrix-
    // sdk's `recovery().recover(...)` internally forwards into
    // `open_secret_store(&str)` and stores the derived key material in
    // SDK-owned (non-Zeroizing) buffers for the secret-storage session.
    // Mitigation would require re-implementing matrix-sdk's recovery
    // pipeline. The `Zeroizing` wrapper on `recovery_key_raw` only
    // protects the un-trimmed source allocation on the carapace side.
    client
        .encryption()
        .recovery()
        .recover(recovery_key)
        .await
        .map_err(|err| {
            let detail = format!(
                "Matrix recovery-key restore failed from {}: {err}",
                path.display()
            );
            let reason = classify_recovery_restore_failure(&detail);
            // matrix-sdk's `RecoveryError` is a distinct type from
            // `matrix_sdk::Error`, so the symmetric peel pattern used
            // by `whoami_with_bounded_retry`,
            // `restore_matrix_session`, and `build_authenticated_client`
            // does not type-check here: there is no
            // `client_api_error_kind()` on `RecoveryError`. The
            // practical exposure is narrow because this site runs
            // AFTER `validate_restored_matrix_session`'s whoami
            // (which already verified the token), so an
            // `M_UNKNOWN_TOKEN` returned by `recover()` would require
            // a sub-second token revocation between whoami-success
            // and the recover call. Operators who do hit it see a
            // generic recovery-key message and fall through to the recover-
            // path docs. If the SDK exposes a typed kind on
            // `RecoveryError` in a future version, route through
            // `AuthTokenRevoked` here for parity.
            recovery_key_restore_failed(reason, detail)
        })?;
    warn!(
        audit_event = "matrix_recovery_key_restored_at_startup",
        path = %path.display(),
        "Matrix recovery key restored during daemon startup"
    );
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixRecoveryKeyRestoredAtStartup,
    ) {
        tracing::warn!(
            error = %err,
            "failed to write matrix_recovery_key_restored_at_startup audit event; tracing-warn is the only forensic signal"
        );
    }
    Ok(())
}

pub(super) async fn maybe_enable_recovery(
    client: &Client,
    config: &MatrixConfig,
    state_dir: &Path,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    _session: &ValidatedMatrixSession,
) -> Result<(), MatrixError> {
    if !config.encrypted() {
        return Ok(());
    }
    let path = matrix_recovery_key_path(state_dir);
    let marker_path = matrix_recovery_minting_marker_path(state_dir);
    let pending_path = matrix_recovery_pending_key_path(state_dir);
    let marker_present =
        recovery_artifact_exists(&marker_path, "Matrix recovery minting marker").await?;
    let key_present = recovery_artifact_exists(&path, "Matrix recovery key").await?;

    // If a "minting in progress" marker is sitting next to the recovery
    // dir, a previous startup minted a server-side secret but crashed
    // before the local persist landed (see write_owner_only_secret_file
    // failure path below). Treat this as the signal to roll back the
    // orphaned server-side state instead of double-minting.
    if marker_present && !key_present {
        if recovery_artifact_exists(&pending_path, "Matrix recovery pending key").await? {
            promote_owner_only_secret_file(&pending_path, &path)
                .await
                .map_err(|err| {
                    recovery_state_io_failed(format!(
                        "Matrix recovery key was preserved at {} after a previous interrupted enable, \
                         but finalizing it to {} failed: {err}",
                        pending_path.display(),
                        path.display()
                    ))
                })?;
            remove_recovery_marker_with_log(&marker_path).await?;
            record_recovery_key_first_mint(
                state,
                state_dir,
                &path,
                crate::logging::audit::MatrixRecoveryKeyFirstMintOutcome::PromotedPendingAfterRestart,
            );
            return Ok(());
        }
        warn!(
            marker = %marker_path.display(),
            "Matrix recovery minting marker found without a recovery key on disk; \
             a previous run minted a server-side recovery secret that wasn't durably \
             persisted locally. Checking remote recovery state before rollback."
        );
        if matrix_recovery_secret_storage_enabled(client).await? {
            return Err(recovery_state_probe_failed(format!(
                "Matrix recovery minting marker exists at {} but no pending/local key was preserved, \
                 and the homeserver already has recovery enabled. Refuse to call disable() because \
                 this may be a valid existing backup; remove the stale marker only after verifying \
                 the recovery key in Element or restoring it with `cara matrix recovery-key restore`.",
                marker_path.display()
            )));
        }
        let rollback = client.encryption().recovery().disable().await;
        rollback.map_err(|err| {
            recovery_state_probe_failed(format!(
                "Matrix recovery had a stale minting marker but disable() failed: {err}. \
                 Disable recovery via Element and rerun."
            ))
        })?;
        remove_recovery_marker_with_log(&marker_path).await?;
    }

    if recovery_artifact_exists(&path, "Matrix recovery key").await? {
        // The key is on disk; if a minting marker is also present it is
        // stale evidence from a prior mint that ultimately succeeded (or
        // from a crash whose key was later promoted by the recovery
        // sequence above, or restored by the operator via
        // `cara matrix recovery-key restore`). Without this cleanup the
        // stale marker survives indefinitely, polluting operator log
        // review and forcing the operator-actionable diagnostic at the
        // top of this function to keep firing for state that has already
        // been reconciled.
        if marker_present {
            cleanup_stale_recovery_minting_marker(&path, &marker_path).await;
        }
        return Ok(());
    }

    // Refuse to call enable() if the homeserver already has recovery
    // configured for this account. enable() in that state may rotate
    // the secret-storage key, and a follow-on local-persist failure
    // would trigger our rollback (disable()), tearing down a
    // previously functional backup the operator never asked us to
    // touch. Direct the operator to retrieve the existing key via
    // Element / `cara matrix recovery-key restore --key-file ...` or stdin
    // instead.
    if matrix_recovery_secret_storage_enabled(client).await? {
        return Err(recovery_state_probe_failed(format!(
            "Matrix recovery is already enabled on the homeserver but no local key file at {} \
             — refuse to mint a new recovery secret (which would invalidate the existing backup). \
             Retrieve the existing key via Element and run `cara matrix recovery-key restore --key-file <file>` \
             or pipe it to `cara matrix recovery-key restore --stdin`.",
            path.display()
        )));
    }

    // Drop a marker file before enable() so a crash between minting and
    // local persist leaves a discoverable "we owe you a rollback"
    // breadcrumb. The marker is removed on successful persist.
    if let Some(parent) = marker_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| recovery_state_io_failed(format!("create matrix state dir: {err}")))?;
    }
    write_recovery_minting_marker_durable(&marker_path).await?;

    let recovery_key = match client.encryption().recovery().enable().await {
        // Wrap in Zeroizing so the freshly-minted backup passphrase is
        // wiped from the heap when this scope exits. The SDK returns
        // a plain `String`; if the persist path below fails or panics
        // before the wrapper drops, a coredump or post-free heap
        // inspection could otherwise recover the key. Symmetric with
        // the discipline applied to `recovery_key_raw` in
        // `maybe_restore_recovery_key`.
        Ok(key) => zeroize::Zeroizing::new(key),
        Err(err) => {
            // Marker no longer represents real server-side state because
            // enable() never produced one. Clean it up — and surface the
            // cleanup error in the operator-visible message if it fails,
            // so a stale marker cannot quietly trigger rollback machinery
            // on the next start.
            let cleanup_note = match remove_recovery_marker_with_log(&marker_path).await {
                Ok(()) => String::new(),
                Err(cleanup_err) => format!(" (additionally, {cleanup_err})"),
            };
            return Err(recovery_state_probe_failed(format!(
                "Matrix recovery enable failed: {err}{cleanup_note}"
            )));
        }
    };
    if let Err(persist_err) = write_owner_only_secret_file(&pending_path, &recovery_key).await {
        // The server-side recovery secret has just been minted, but the
        // generated key could not even be preserved in the local pending
        // slot. Roll back because there is no durable local copy to
        // promote on the next start.
        let rollback_msg = match client.encryption().recovery().disable().await {
            Ok(()) => match remove_recovery_marker_with_log(&marker_path).await {
                Ok(()) => "server-side recovery disabled".to_string(),
                Err(cleanup_err) => format!(
                    "server-side recovery disabled but minting-marker cleanup failed: {cleanup_err}"
                ),
            },
            Err(disable_err) => format!(
                "server-side recovery rollback failed: {disable_err}; \
                 minting marker left at {} for next-start rollback retry",
                marker_path.display()
            ),
        };
        return Err(recovery_state_io_failed(format!(
            "failed to preserve Matrix recovery key at {}: {persist_err}; {rollback_msg}",
            pending_path.display()
        )));
    }

    if let Err(promote_err) = promote_owner_only_secret_file(&pending_path, &path).await {
        return Err(recovery_state_io_failed(format!(
            "Matrix recovery key was durably preserved at {}, but finalizing it to {} failed: {promote_err}. \
             The server-side recovery key was left enabled so the preserved pending key remains valid; \
             fix the file conflict and restart so Carapace can promote the pending key.",
            pending_path.display(),
            path.display()
        )));
    }

    // Persist landed: clear the minting marker so next start doesn't
    // try to roll back.
    remove_recovery_marker_with_log(&marker_path).await?;
    record_recovery_key_first_mint(
        state,
        state_dir,
        &path,
        crate::logging::audit::MatrixRecoveryKeyFirstMintOutcome::Minted,
    );
    Ok(())
}

/// Probe a recovery-key file for at least one non-whitespace byte.
///
/// `recovery_artifact_exists` is a pure `metadata()` check, so a
/// zero-byte / whitespace-only key file (left by a pre-atomic-write
/// build, a hostile FS, or an aborted restore that crashed between
/// `create_new` and `write_all`) reads as "present" — but cannot
/// decrypt anything. Used by `cleanup_stale_recovery_minting_marker`
/// to decide whether the minting marker can be safely retired:
/// removing it without a valid key on disk would discard the only
/// breadcrumb pointing at an orphaned server-side recovery secret.
pub(super) async fn recovery_key_file_has_secret_bytes(path: &Path) -> Result<bool, MatrixError> {
    const PROBE_CAP_BYTES: u64 = 4096;
    let path_owned = path.to_path_buf();
    match tokio::time::timeout(MATRIX_RUNTIME_OPERATION_TIMEOUT, async move {
        // O_NONBLOCK so open(2) doesn't block even if a planted FIFO
        // would otherwise hang the spawn_blocking pool until the
        // outer timeout fires. Symlinks ARE intentionally followed
        // here (operator-routed secret-management tooling); the
        // post-open is_file() check refuses FIFO/socket/device.
        // Wrapped in spawn_blocking so std OpenOptions can be used
        // without ferrying flags through tokio's OpenOptions.
        let buf = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            use std::io::Read;
            let mut file = match crate::paths::open_regular_file_no_hang(&path_owned)? {
                Some(file) => file,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "recovery key file missing during probe",
                    ));
                }
            };
            let mut buf = Vec::new();
            // `take(PROBE_CAP_BYTES)` upper-bounds the read so a
            // huge attacker-routed symlink target cannot OOM us.
            file.by_ref().take(PROBE_CAP_BYTES).read_to_end(&mut buf)?;
            Ok(buf)
        })
        .await
        .map_err(|join_err| std::io::Error::other(format!("join blocking probe: {join_err}")))??;
        Ok::<Vec<u8>, std::io::Error>(buf)
    })
    .await
    {
        Ok(Ok(buf)) => Ok(buf.iter().any(|byte| !byte.is_ascii_whitespace())),
        Ok(Err(err)) => Err(recovery_state_io_failed(format!(
            "failed to probe Matrix recovery key at {} for stale-marker cleanup: {err}",
            path.display()
        ))),
        Err(_) => Err(recovery_state_io_failed(format!(
            "timed out probing Matrix recovery key at {} for stale-marker cleanup after {} seconds",
            path.display(),
            MATRIX_RUNTIME_OPERATION_TIMEOUT.as_secs()
        ))),
    }
}

/// Best-effort cleanup of a stale recovery-minting marker.
///
/// Two startup invariants:
/// 1. Never destructively act on a recovery key file whose contents
///    have not been confirmed (a zero-byte file may indicate an
///    aborted restore whose marker is the only remaining trace of an
///    orphaned server-side mint). If the probe reports no secret
///    bytes or errors, leave the marker for operator inspection.
/// 2. Never refuse to start a daemon whose recovery key IS fully on
///    disk just because a stale marker happens to be unremovable
///    (transient EBUSY from an AV scanner, EACCES, ENOSPC on the
///    parent fsync). Demote the cleanup error to a warning; the
///    marker will be re-evaluated on the next start.
pub(super) async fn cleanup_stale_recovery_minting_marker(key_path: &Path, marker_path: &Path) {
    match recovery_key_file_has_secret_bytes(key_path).await {
        Ok(true) => {
            if let Err(err) = remove_recovery_marker_with_log(marker_path).await {
                warn!(
                    marker = %marker_path.display(),
                    error = %err,
                    "Matrix recovery: stale minting-marker cleanup deferred; \
                     marker will be re-evaluated on next start"
                );
            }
        }
        Ok(false) => {
            warn!(
                key = %key_path.display(),
                marker = %marker_path.display(),
                "Matrix recovery key file contains no secret bytes; \
                 leaving the minting marker in place for operator inspection \
                 — restore the recovery key or delete the empty file"
            );
        }
        Err(err) => {
            warn!(
                key = %key_path.display(),
                marker = %marker_path.display(),
                error = %err,
                "Matrix recovery: probe of key file failed; leaving the minting marker in place"
            );
        }
    }
}

pub(super) async fn recovery_artifact_exists(
    path: &Path,
    label: &'static str,
) -> Result<bool, MatrixError> {
    match tokio::time::timeout(MATRIX_RUNTIME_OPERATION_TIMEOUT, tokio::fs::metadata(path)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(Err(err)) => Err(recovery_state_io_failed(format!(
            "failed to inspect {label} at {}: {err}",
            path.display()
        ))),
        Err(_) => Err(recovery_state_io_failed(format!(
            "timed out inspecting {label} at {} after {} seconds",
            path.display(),
            MATRIX_RUNTIME_OPERATION_TIMEOUT.as_secs()
        ))),
    }
}

pub(super) fn record_recovery_key_first_mint(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    state_dir: &Path,
    path: &Path,
    outcome: crate::logging::audit::MatrixRecoveryKeyFirstMintOutcome,
) {
    let minted_at = now_millis();
    state.write().status.first_recovery_key_minted_at = Some(minted_at);
    // Tracing-warn for human-readable log dashboards; the
    // operator-facing copy still tells them to capture the
    // recovery key. The `audit_event = "..."` field matches the
    // durable audit event name below so log+audit grep on the
    // same string returns both signals.
    let outcome_label = match outcome {
        crate::logging::audit::MatrixRecoveryKeyFirstMintOutcome::Minted => "minted",
        crate::logging::audit::MatrixRecoveryKeyFirstMintOutcome::PromotedPendingAfterRestart => {
            "promoted_pending_after_restart"
        }
    };
    warn!(
        audit_event = "matrix_recovery_key_first_mint",
        outcome = outcome_label,
        minted_at,
        path = %path.display(),
        "Matrix recovery key created and stored locally; capture the owner-only recovery key before relying on encrypted Matrix backup"
    );
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixRecoveryKeyFirstMint { outcome, minted_at },
    ) {
        tracing::warn!(
            error = %err,
            "failed to write matrix_recovery_key_first_mint audit event; tracing-warn is the only forensic signal"
        );
    }
}

/// Remove a recovery marker and fsync its parent directory.
///
/// Recovery markers are startup-routing state, not incidental temp files.
/// A caller that reports recovery success while cleanup failed can send the
/// next daemon start down the wrong recovery branch, so failures propagate to
/// the operator-visible result instead of remaining warning-only.
pub(super) async fn remove_recovery_marker_with_log(marker_path: &Path) -> Result<(), MatrixError> {
    remove_recovery_artifact_with_log(marker_path, "marker").await
}

pub(super) async fn remove_recovery_artifact_with_log(
    path: &Path,
    label: &'static str,
) -> Result<(), MatrixError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {
            sync_parent_dir_or_err(path).await.map_err(|err| {
                recovery_state_io_failed(format!(
                    "Matrix recovery {label} cleanup removed {} but parent fsync failed: {err}",
                    path.display()
                ))
            })?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            warn!(
                path = %path.display(),
                label,
                error = %err,
                "Matrix recovery artifact cleanup failed; remove the file manually if it persists"
            );
            Err(recovery_state_io_failed(format!(
                "failed to remove Matrix recovery {label} at {}: {err}",
                path.display()
            )))
        }
    }
}

/// Atomic, fsynced write of the recovery-minting marker file.
///
/// `tokio::fs::write(...)` returns once the kernel has buffered the
/// data; a power loss before the page-cache flush erases the marker.
/// The marker is the *only* breadcrumb that lets the next start roll
/// back an orphaned server-side `recovery().enable()`, so it must be
/// durable before `enable()` runs. Tmp-then-rename + parent-dir fsync
/// matches the discipline used by `write_owner_only_secret_file` for
/// the recovery key itself.
pub(super) async fn write_recovery_minting_marker_durable(
    marker_path: &Path,
) -> Result<(), MatrixError> {
    write_recovery_marker_durable(
        marker_path,
        b"recovery-minting-in-progress\n",
        "recovery-minting",
    )
    .await
}

pub(super) async fn write_recovery_rotation_marker_durable(
    marker_path: &Path,
    previous_key_sha256: Option<String>,
) -> Result<(), MatrixError> {
    write_recovery_rotation_marker_stage_durable(
        marker_path,
        RecoveryKeyRotationMarkerStage::Started,
        None,
        previous_key_sha256,
    )
    .await
}

pub(super) async fn write_recovery_rotation_marker_stage_durable(
    marker_path: &Path,
    stage: RecoveryKeyRotationMarkerStage,
    key_sha256: Option<String>,
    previous_key_sha256: Option<String>,
) -> Result<(), MatrixError> {
    let marker = RecoveryKeyRotationMarker {
        stage,
        key_sha256,
        previous_key_sha256,
        updated_at_ms: now_millis(),
        legacy_text_marker: false,
    };
    let content = serde_json::to_vec(&marker).map_err(|err| {
        recovery_state_io_failed(format!("serialize recovery-rotation marker: {err}"))
    })?;
    write_recovery_marker_durable(marker_path, &content, "recovery-rotation").await
}

pub(super) async fn write_recovery_marker_durable(
    marker_path: &Path,
    content: &[u8],
    label: &'static str,
) -> Result<(), MatrixError> {
    if let Some(parent) = marker_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| recovery_state_io_failed(format!("create matrix state dir: {err}")))?;
    }
    let marker_path_owned = marker_path.to_path_buf();
    let marker_for_err = marker_path_owned.clone();
    let content = content.to_vec();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write;
        let tmp_path = secret_file_temp_path(&marker_path_owned);
        {
            // Use OpenOptions with explicit `mode(0o600)` for
            // consistency with neighbouring secret-file writers, even
            // though the marker itself contains no secret material.
            // This forecloses umask drift if a later contributor
            // copies this code as a template for a real secret writer.
            // Route through the canonical helper for O_NOFOLLOW + O_EXCL
            // + 0o600 defense-in-depth.
            let mut file = crate::paths::create_atomic_tmp_owner_only(&tmp_path)
                .map_err(|err| format!("create marker tmp: {err}"))?;
            let result = (|| -> std::io::Result<()> {
                file.write_all(&content)?;
                if !content.ends_with(b"\n") {
                    file.write_all(b"\n")?;
                }
                file.sync_all()
            })();
            if let Err(err) = result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("write marker tmp: {err}"));
            }
        }
        if let Err(err) = std::fs::rename(&tmp_path, &marker_path_owned) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("rename marker: {err}"));
        }
        // Parent-dir fsync via shared helper. The marker's whole
        // point is to be the rollback breadcrumb on crash, so a
        // silent fsync would defeat the durable-write contract this
        // function advertises. Routes through the shared helper so
        // Windows takes the documented no-op (NTFS journal handles
        // dirent durability) instead of erroring with
        // ERROR_ACCESS_DENIED.
        crate::paths::sync_parent_dir_blocking(&marker_path_owned)
            .map_err(|err| format!("fsync marker parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| recovery_state_io_failed(format!("marker write join: {err}")))?
    .map_err(|err| {
        recovery_state_io_failed(format!(
            "failed to write {label} marker at {}: {err}",
            marker_for_err.display()
        ))
    })
}

pub(crate) fn matrix_recovery_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key")
}

pub(crate) fn matrix_recovery_minting_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key.minting")
}

pub(crate) fn matrix_recovery_rotating_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key.rotating")
}

pub(crate) fn matrix_recovery_pending_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key.pending")
}

pub(crate) fn matrix_recovery_cleanup_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key.cleanup")
}

pub(super) fn recovery_key_sha256(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.trim().as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) async fn recovery_key_file_sha256(path: &Path) -> Result<Option<String>, MatrixError> {
    read_recovery_key_file_to_string_bounded(path, "Matrix recovery key digest")
        .await
        .map(|content| content.map(|content| recovery_key_sha256(&content)))
}

/// Cap on Matrix recovery-key files. A real recovery key is ~50-90
/// ASCII bytes (base58-encoded with a short format prefix); 4 KiB is
/// generous for unusual encodings + trailing whitespace while still
/// bounding the worst case against a corrupted/hostile artifact at
/// `state_dir/matrix/recovery_key{,.pending,.minting}`.
pub(crate) const MATRIX_RECOVERY_KEY_FILE_MAX_BYTES: u64 = 4 * 1024;

pub(super) async fn read_recovery_key_file_to_string_bounded(
    path: &Path,
    label: &'static str,
) -> Result<Option<zeroize::Zeroizing<String>>, MatrixError> {
    // Mirror `read_matrix_store_passphrase_file` (matrix.rs:2276): a
    // metadata-size pre-check + `.take(cap + 1)` post-read guard.
    // Previously the function was named `_bounded` but called
    // `tokio::fs::read_to_string` with no cap whatsoever, so a
    // multi-GB file at the path (filesystem fault, hostile co-tenant
    // with write access to state_dir/matrix/, accidental symlink to
    // a large file — `tokio::fs::read_to_string` does follow symlinks)
    // would buffer entirely into the daemon. Also, the intermediate
    // `Vec<u8>` reallocations done by `read_to_string` are NOT zeroed
    // — wrapping into Zeroizing only zeroes the FINAL allocation. The
    // bounded read fixes both: with a fixed 4 KiB ceiling the
    // intermediate growth is at most one allocation.
    let path_buf = path.to_path_buf();
    let label_for_blocking = label;
    let result = tokio::time::timeout(
        MATRIX_RUNTIME_OPERATION_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            read_recovery_key_file_to_string_bounded_blocking(&path_buf, label_for_blocking)
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(result))) => Ok(result),
        Ok(Ok(Err(err))) => Err(err),
        Ok(Err(join_err)) => Err(recovery_state_io_failed(format!(
            "{label} read task panicked: {join_err}"
        ))),
        Err(_) => Err(recovery_state_io_failed(format!(
            "timed out reading {label} after {} seconds",
            MATRIX_RUNTIME_OPERATION_TIMEOUT.as_secs()
        ))),
    }
}

/// Render an io::Error path-free. Used in the recovery-key reader so
/// the artifact path does not leak into operator-visible errors per
/// the SECURITY invariant. `paths::open_regular_file_no_hang` and
/// the `_no_follow` variant return path-free `InvalidData` errors
/// for file-type rejections, so the full Display is safe to forward.
/// For other ErrorKinds (NotFound, PermissionDenied, etc.) we emit
/// just the kind label.
pub(super) fn io_error_kind_label(err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::InvalidData {
        err.to_string()
    } else {
        format!("{}", err.kind())
    }
}

pub(super) fn read_recovery_key_file_to_string_bounded_blocking(
    path: &Path,
    label: &'static str,
) -> Result<Option<zeroize::Zeroizing<String>>, MatrixError> {
    use std::io::Read;
    // SECURITY: Error messages must NOT include `path.display()`. The
    // project invariant is that recovery-key artifact paths never appear
    // in operator-visible errors (so an operator pasting an error into
    // a support ticket can't leak the artifact location). Pinned by
    // test_recovery_key_digest_read_errors_do_not_expose_paths and
    // mirrored at cli/mod.rs:15614 for the cleanup-error helpers. The
    // operator already knows the conventional artifact location from
    // docs; the underlying io::Error kind is enough context. Keep paths
    // in server-side breadcrumbs (tracing::warn!/error!) only.
    // SECURITY: open with O_NONBLOCK + fd-based `metadata()` (= fstat
    // on the held fd). Two TOCTOU classes both close here:
    //   (1) same-uid attacker swaps the dirent for a symlink-to-FIFO
    //       between a path-stat and the open → the prior bare
    //       `File::open(path)` would BLOCK during `open(2)` itself
    //       waiting for a FIFO writer (the post-open fstat never
    //       runs). O_NONBLOCK makes open(2) return immediately.
    //   (2) attacker swaps the dirent for a regular file with
    //       attacker-chosen contents → fstat on the held fd reflects
    //       the actual fd we will read from, not a path resolution
    //       that can be retargeted.
    //
    // Symlinks ARE intentionally followed at this site (operator-
    // routed secret-management tooling per the documented design);
    // the post-open `is_file()` check still refuses
    // symlink→FIFO/socket because the held fd's file_type is the
    // resolved target. Mirrors `read_matrix_store_passphrase_file`.
    let file = match crate::paths::open_regular_file_no_hang(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(err) => {
            // Preserve the path-stripping invariant: the helper's
            // error message embeds `path.display()` for general
            // operator debugging, but recovery-key artifact paths
            // must NEVER appear in operator-visible errors (see
            // SECURITY comment above). Translate the io::Error
            // via its kind only.
            return Err(recovery_state_io_failed(format!(
                "failed to read {label}: open failed: {}",
                io_error_kind_label(&err)
            )));
        }
    };
    let metadata = file.metadata().map_err(|err| {
        recovery_state_io_failed(format!("failed to read {label}: stat failed: {err}"))
    })?;
    if !metadata.is_file() {
        return Err(recovery_state_io_failed(format!(
            "failed to read {label}: not a regular file (symlinks to regular files are allowed)"
        )));
    }
    if metadata.len() > MATRIX_RECOVERY_KEY_FILE_MAX_BYTES {
        return Err(recovery_state_io_failed(format!(
            "failed to read {label}: exceeds {} bytes",
            MATRIX_RECOVERY_KEY_FILE_MAX_BYTES
        )));
    }
    let mut buf = zeroize::Zeroizing::new(String::with_capacity(
        metadata.len().min(MATRIX_RECOVERY_KEY_FILE_MAX_BYTES) as usize,
    ));
    file.take(MATRIX_RECOVERY_KEY_FILE_MAX_BYTES + 1)
        .read_to_string(&mut buf)
        .map_err(|err| recovery_state_io_failed(format!("failed to read {label}: {err}")))?;
    if buf.len() as u64 > MATRIX_RECOVERY_KEY_FILE_MAX_BYTES {
        return Err(recovery_state_io_failed(format!(
            "failed to read {label}: exceeds {} bytes",
            MATRIX_RECOVERY_KEY_FILE_MAX_BYTES
        )));
    }
    Ok(Some(buf))
}

/// Recovery rotation markers are ≤ 1 KiB of JSON in practice (a
/// few short string fields). Cap at 4 KiB — same class as the
/// installation_id cap. Without this a same-uid attacker swapping
/// the marker for a multi-GB file would OOM the daemon on every
/// startup hitting the interrupted-rotation recovery branch.
pub(super) const MATRIX_RECOVERY_ROTATION_MARKER_MAX_BYTES: u64 = 4 * 1024;

pub(super) async fn load_recovery_rotation_marker(
    marker_path: &Path,
    state_dir: &Path,
) -> Result<RecoveryKeyRotationMarker, MatrixError> {
    load_recovery_rotation_marker_with_timeout(
        marker_path,
        state_dir,
        MATRIX_RUNTIME_OPERATION_TIMEOUT,
        read_capped_marker_or_journal(
            marker_path.to_path_buf(),
            MATRIX_RECOVERY_ROTATION_MARKER_MAX_BYTES,
        ),
    )
    .await
}

/// Read a small marker / journal file with O_NOFOLLOW + size cap.
/// Used by `load_recovery_rotation_marker`,
/// `inspect_matrix_recovery_cleanup_journal`, and the CLI
/// `load_matrix_recovery_cleanup_journal`. Defends against same-
/// uid symlink-to-large-file OOM at startup.
pub(super) async fn read_capped_marker_or_journal(
    path: PathBuf,
    max_bytes: u64,
) -> std::io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let file = open_owner_only_secret_file_for_read(&path)?;
        let metadata = file.metadata()?;
        if metadata.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} exceeds {} bytes (size cap)", path.display(), max_bytes),
            ));
        }
        let mut buf = Vec::new();
        file.take(max_bytes + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} exceeds {} bytes (post-read)", path.display(), max_bytes),
            ));
        }
        Ok(buf)
    })
    .await
    .map_err(|err| std::io::Error::other(format!("read task: {err}")))?
}

pub(super) async fn load_recovery_rotation_marker_with_timeout<F>(
    marker_path: &Path,
    state_dir: &Path,
    timeout: Duration,
    read: F,
) -> Result<RecoveryKeyRotationMarker, MatrixError>
where
    F: std::future::Future<Output = std::io::Result<Vec<u8>>>,
{
    let content = match tokio::time::timeout(timeout, read).await {
        Ok(Ok(content)) => content,
        Ok(Err(err)) => {
            return Err(recovery_state_io_failed(format!(
                "failed to read Matrix recovery-key rotation marker at {}: {err}",
                marker_path.display()
            )));
        }
        Err(_) => {
            return Err(recovery_state_io_failed(format!(
                "timed out reading Matrix recovery-key rotation marker at {} after {} seconds",
                marker_path.display(),
                timeout.as_secs()
            )));
        }
    };
    parse_recovery_rotation_marker_bytes(&content, state_dir)
}

pub(super) fn parse_recovery_rotation_marker_bytes(
    content: &[u8],
    state_dir: &Path,
) -> Result<RecoveryKeyRotationMarker, MatrixError> {
    match serde_json::from_slice::<RecoveryKeyRotationMarker>(content.trim_ascii()) {
        Ok(marker) => Ok(marker),
        Err(_) if content.trim_ascii() == b"recovery-rotation-in-progress" => {
            Ok(RecoveryKeyRotationMarker {
                stage: RecoveryKeyRotationMarkerStage::Started,
                key_sha256: None,
                previous_key_sha256: None,
                updated_at_ms: 0,
                legacy_text_marker: true,
            })
        }
        Err(err) => {
            let reason = if recovery_rotation_marker_bytes_are_typed(content.trim_ascii()) {
                crate::logging::audit::MatrixRecoveryKeyRotationMarkerInvalidReason::CorruptTypedMarker
            } else {
                crate::logging::audit::MatrixRecoveryKeyRotationMarkerInvalidReason::UnknownLegacyMarker
            };
            // SECURITY: durable audit. This is the refusal path where
            // the daemon will return Err to the caller (typically
            // `recover_interrupted_recovery_key_rotation`), which
            // aborts startup. Lossy `audit::audit()` could drop this
            // event under audit-channel saturation, leaving the
            // operator with no forensic record of *why* startup
            // refused. Same lesson as Batch 80 / 86 — refusals that
            // gate irreversible operator action must be durable.
            if let Err(audit_err) = crate::logging::audit::audit_durable_for_state_dir(
                state_dir.to_path_buf(),
                crate::logging::audit::AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid {
                    reason: reason.clone(),
                },
            ) {
                tracing::warn!(
                    error = %audit_err,
                    "failed to write matrix_recovery_key_rotation_marker_invalid audit event; tracing-warn is the only forensic signal"
                );
            }
            warn!(
                audit_event = "matrix_recovery_key_rotation_marker_invalid",
                reason = ?reason,
                error = %err,
                "refusing to recover Matrix recovery-key rotation from an invalid marker"
            );
            let operator_reason = match reason {
                crate::logging::audit::MatrixRecoveryKeyRotationMarkerInvalidReason::CorruptTypedMarker => {
                    "typed recovery-key rotation marker is malformed"
                }
                crate::logging::audit::MatrixRecoveryKeyRotationMarkerInvalidReason::UnknownLegacyMarker => {
                    "recovery-key rotation marker is not a supported typed or legacy marker"
                }
            };
            Err(recovery_state_io_failed(format!(
                "Matrix recovery-key rotation marker is invalid: {operator_reason}. \
                 Refusing startup repair until recovery_key.rotating and recovery_key.pending \
                 are inspected without trusting the pending key."
            )))
        }
    }
}

pub(super) fn recovery_rotation_marker_bytes_are_typed(content: &[u8]) -> bool {
    let content = content.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(content);
    content
        .first()
        .is_some_and(|byte| matches!(byte, b'{' | b'['))
}

pub(super) async fn matrix_recovery_secret_storage_enabled(
    client: &Client,
) -> Result<bool, MatrixError> {
    client
        .encryption()
        .secret_storage()
        .is_enabled()
        .await
        .map_err(|err| recovery_state_probe_failed(format!("check Matrix recovery state: {err}")))
}

pub(super) fn preflight_matrix_session_persistence() -> Result<(), MatrixError> {
    if crate::config::config_password().is_none() {
        return Err(MatrixError::TokenPersistence(
            "CARAPACE_CONFIG_PASSWORD is required before Matrix password login so the resulting access token can be persisted as an encrypted config secret".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatrixRecoveryKeyRotateOutcome {
    pub path: PathBuf,
    pub rotated_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecoveryKeyRotationMarkerStage {
    Started,
    PendingKeyWritten,
    FinalKeyReplaced,
}

/// Wire-format version for the Matrix recovery-key cleanup journal
/// at `matrix/recovery_key.cleanup`. The journal is a single-record
/// file written when `cara matrix recovery-key restore` enters the
/// post-restore artifact cleanup phase, and removed by the daemon
/// on the next successful boot after cleanup completes.
///
/// **Downgrade contract.** The version is checked exactly (no
/// "older-or-equal" tolerance) because the journal records WHICH
/// artifacts to clean up; if the artifact-role enum or its semantics
/// change between versions, an older daemon acting on a newer-version
/// journal could skip artifacts it doesn't recognize and leave key
/// material on disk under operator-unverified provenance. That is
/// strictly worse than refusing startup repair and waiting for
/// operator intervention. Consequence: downgrading after `cara matrix
/// recovery-key restore` but before the post-restore daemon boot
/// completes cleanup is NOT supported. The error message in
/// `inspect_matrix_recovery_cleanup_journal` and
/// `load_matrix_recovery_cleanup_journal` directs operators to
/// either run the newer binary once to let cleanup complete, or
/// manually inspect and remove `matrix/recovery_key.{pending,minting,
/// rotating}` artifacts and then the journal file.
pub(crate) const MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MatrixRecoveryCleanupJournal {
    pub(crate) version: u8,
    pub(crate) phase: MatrixRecoveryCleanupJournalPhase,
    pub(crate) artifacts: Vec<MatrixRecoveryCleanupJournalArtifact>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatrixRecoveryCleanupJournalPhase {
    // SECURITY: intentionally fail-closed on unknown wire values per
    // the "Downgrade contract" comment on `MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION`
    // above. Adding a `deserialize_with` fallback here would defeat
    // the documented refusal to act on a journal whose semantics this
    // binary does not understand.
    Started,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MatrixRecoveryCleanupJournalArtifact {
    pub(crate) role: MatrixRecoveryCleanupArtifactRole,
    pub(crate) path: String,
    pub(crate) expected_provenance: String,
    pub(crate) result: MatrixRecoveryCleanupArtifactResult,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatrixRecoveryCleanupArtifactRole {
    RotationMarker,
    MintingMarker,
    PendingKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MatrixRecoveryCleanupArtifactResult {
    pub(crate) state: MatrixRecoveryCleanupArtifactResultState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_kind: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatrixRecoveryCleanupArtifactResultState {
    Pending,
    Removed,
    NotFound,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct RecoveryKeyRotationMarker {
    pub(super) stage: RecoveryKeyRotationMarkerStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) key_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) previous_key_sha256: Option<String>,
    pub(super) updated_at_ms: i64,
    #[serde(skip)]
    pub(super) legacy_text_marker: bool,
}

pub(crate) async fn rotate_matrix_recovery_key_for_cli(
    config: &MatrixConfig,
    state_dir: &Path,
) -> Result<MatrixRecoveryKeyRotateOutcome, MatrixError> {
    if !config.encrypted() {
        return Err(recovery_state_probe_failed(
            "matrix recovery-key rotate requires matrix.encrypted=true".to_string(),
        ));
    }

    recover_interrupted_recovery_key_rotation(state_dir).await?;

    let key_path = matrix_recovery_key_path(state_dir);
    if !recovery_artifact_exists(&key_path, "Matrix recovery key").await? {
        return Err(recovery_state_probe_failed(format!(
            "Matrix recovery key is unavailable at {}; restore the current key first with \
             `cara matrix recovery-key restore --key-file <file>` or `--stdin` before rotating",
            key_path.display()
        )));
    }

    let marker_path = matrix_recovery_rotating_marker_path(state_dir);
    let pending_path = matrix_recovery_pending_key_path(state_dir);
    if recovery_artifact_exists(&pending_path, "Matrix recovery pending key").await? {
        return Err(recovery_state_probe_failed(format!(
            "Matrix recovery-key pending file already exists at {}; restart the daemon to promote \
             it or move it aside after verifying the key in Element before rotating again",
            pending_path.display()
        )));
    }

    let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
    let client = build_authenticated_client(config, state_dir, &state).await?;
    let previous_key_sha256 = recovery_key_file_sha256(&key_path).await?;
    write_recovery_rotation_marker_durable(&marker_path, previous_key_sha256.clone()).await?;

    let recovery_key = match client.encryption().recovery().reset_key().await {
        Ok(key) => zeroize::Zeroizing::new(key),
        Err(err) => {
            return Err(recovery_state_probe_failed(format!(
                "Matrix recovery-key rotate failed before a new key was returned: {err}. \
                 The rotation marker remains in place so startup fails closed until the \
                 local current/pending key state is inspected."
            )));
        }
    };

    if let Err(err) = write_owner_only_secret_file(&pending_path, &recovery_key).await {
        return Err(recovery_state_io_failed(format!(
            "Matrix recovery key was rotated on the homeserver, but preserving the new key at {} failed: {err}. \
             Do not restart until the key has been recovered from Element or the pending write failure is resolved.",
            pending_path.display()
        )));
    }
    let key_sha256 = recovery_key_sha256(&recovery_key);
    write_recovery_rotation_marker_stage_durable(
        &marker_path,
        RecoveryKeyRotationMarkerStage::PendingKeyWritten,
        Some(key_sha256.clone()),
        previous_key_sha256.clone(),
    )
    .await?;
    // `key_sha256` is computed from the in-memory `recovery_key` we
    // just wrote to `pending_path` via `write_owner_only_secret_file`.
    // Passing it as `expected_src_digest` triggers the rename helper's
    // re-hash-before-rename check, refusing if a same-uid attacker
    // swapped the dirent between our write and this rename.
    replace_owner_only_secret_file(&pending_path, &key_path, &key_sha256)
        .await
        .map_err(|err| {
            recovery_state_io_failed(format!(
                "Matrix recovery key was rotated and preserved at {}, but replacing {} failed: {err}. \
                 Keep the pending file; restart will promote it before Matrix recovery.",
                pending_path.display(),
                key_path.display()
            ))
        })?;
    write_recovery_rotation_marker_stage_durable(
        &marker_path,
        RecoveryKeyRotationMarkerStage::FinalKeyReplaced,
        Some(key_sha256),
        previous_key_sha256,
    )
    .await?;
    remove_recovery_marker_with_log(&marker_path).await?;

    let rotated_at = now_millis();
    warn!(
        audit_event = "matrix_recovery_key_rotate",
        rotated_at,
        path = %key_path.display(),
        "Matrix recovery key rotated; previous recovery key is abandoned"
    );
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixRecoveryKeyRotated { rotated_at },
    ) {
        tracing::warn!(
            error = %err,
            "failed to write matrix_recovery_key_rotate audit event; tracing-warn is the only forensic signal"
        );
    }
    Ok(MatrixRecoveryKeyRotateOutcome {
        path: key_path,
        rotated_at,
    })
}

pub(super) fn recovery_marker_stage_for_audit(
    stage: RecoveryKeyRotationMarkerStage,
) -> crate::logging::audit::MatrixRecoveryKeyRotationStage {
    match stage {
        RecoveryKeyRotationMarkerStage::Started => {
            crate::logging::audit::MatrixRecoveryKeyRotationStage::Started
        }
        RecoveryKeyRotationMarkerStage::PendingKeyWritten => {
            crate::logging::audit::MatrixRecoveryKeyRotationStage::PendingKeyWritten
        }
        RecoveryKeyRotationMarkerStage::FinalKeyReplaced => {
            crate::logging::audit::MatrixRecoveryKeyRotationStage::FinalKeyReplaced
        }
    }
}

/// Emit a durable `MatrixCrossSigningBootstrapped` audit event
/// alongside the existing `tracing::warn!` at both bootstrap
/// branches in `bootstrap_cross_signing_if_needed_with_uia`.
/// Best-effort durability — see the rotate-recovered helper below
/// for the rationale on the tracing-fallback contract.
pub(super) fn emit_cross_signing_bootstrapped_audit(
    state_dir: &Path,
    user_id: String,
    outcome: crate::logging::audit::MatrixCrossSigningBootstrapOutcome,
) {
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixCrossSigningBootstrapped { outcome, user_id },
    ) {
        tracing::warn!(
            error = %err,
            "failed to write matrix_cross_signing_bootstrapped audit event; tracing-warn is the only forensic signal"
        );
    }
}

/// Emit a durable `MatrixCrossSigningBootstrapFailed` audit event
/// alongside the existing `MatrixError` return. Without this, an
/// account left half-bootstrapped (UIA consumed, identity not
/// installed) has only a tracing line that operators may lose to
/// log rotation. Same forensic tier as the success-side audit
/// emission.
pub(super) fn emit_cross_signing_bootstrap_failed_audit(
    state_dir: &Path,
    user_id: String,
    outcome: crate::logging::audit::MatrixCrossSigningBootstrapFailureOutcome,
    error_kind: String,
) {
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixCrossSigningBootstrapFailed {
            outcome,
            user_id: crate::logging::audit::truncate_audit_free_text_field(
                &user_id,
                crate::logging::audit::AUDIT_FREE_TEXT_FIELD_MAX_BYTES,
            ),
            // Defense-in-depth: although `error_kind` is documented as a
            // short classification string, callers that pass a raw
            // homeserver-derived error must not be able to push the audit
            // line past `AUDIT_LINE_MAX_BYTES` and silently drop the
            // entry.
            error_kind: crate::logging::audit::truncate_audit_free_text_field(
                &error_kind,
                crate::logging::audit::AUDIT_FREE_TEXT_FIELD_MAX_BYTES,
            ),
        },
    ) {
        tracing::warn!(
            error = %err,
            "failed to write matrix_cross_signing_bootstrap_failed audit event; tracing-warn is the only forensic signal"
        );
    }
}

/// Emit a durable `MatrixRecoveryKeyRotateRecovered` audit event
/// alongside the existing `tracing::warn!` at every successful-
/// recovery branch of `recover_interrupted_recovery_key_rotation`.
///
/// Audit-write failures are logged but non-fatal: the tracing-warn
/// is the operator's primary signal, and the audit event is
/// purely-additive durability. A1's post-B97 audit gave a HIGH-
/// forensic on the 6 tracing-warn-only recovery sites; this helper
/// closes the gap with one call per site.
pub(super) fn emit_recovery_rotate_recovered_audit(
    state_dir: &Path,
    marker_stage: crate::logging::audit::MatrixRecoveryKeyRotationStage,
    outcome: crate::logging::audit::MatrixRecoveryKeyRotateRecoveredOutcome,
) {
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(
        state_dir.to_path_buf(),
        crate::logging::audit::AuditEvent::MatrixRecoveryKeyRotateRecovered {
            marker_stage,
            outcome,
        },
    ) {
        tracing::warn!(
            error = %err,
            "failed to write matrix_recovery_key_rotate_recovered audit event; tracing-warn is the only forensic signal"
        );
    }
}

pub(super) fn recovery_key_state_for_audit(
    digest: Option<&str>,
    previous_digest: Option<&str>,
    new_digest: Option<&str>,
) -> crate::logging::audit::MatrixRecoveryKeyState {
    let Some(digest) = digest else {
        return crate::logging::audit::MatrixRecoveryKeyState::Missing;
    };
    // SECURITY (defense-in-depth): use constant-time comparison for digest
    // equality. These SHA-256 digests are of non-secret content (they are
    // themselves digests of operator-known recovery-key file paths), so the
    // plaintext timing oracle is weak, but the digests gate marker-stage
    // transitions and `replace_owner_only_secret_file` invocations. Consistent
    // use of `auth::timing_safe_eq` matches `sessions/integrity.rs:483` and
    // prevents a future code change from quietly introducing a real leak.
    if previous_digest.is_some_and(|previous| crate::auth::timing_safe_eq(digest, previous)) {
        return crate::logging::audit::MatrixRecoveryKeyState::MatchesPreviousKey;
    }
    if new_digest.is_some_and(|new| crate::auth::timing_safe_eq(digest, new)) {
        return crate::logging::audit::MatrixRecoveryKeyState::MatchesNewKey;
    }
    if previous_digest.is_none() && new_digest.is_none() {
        crate::logging::audit::MatrixRecoveryKeyState::Unknown
    } else {
        crate::logging::audit::MatrixRecoveryKeyState::Mismatch
    }
}

pub(super) fn recovery_pending_refusal_event(
    marker: &RecoveryKeyRotationMarker,
    reason: crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason,
    current_digest: Option<&str>,
    pending_digest: Option<&str>,
) -> crate::logging::audit::AuditEvent {
    crate::logging::audit::AuditEvent::MatrixRecoveryKeyPendingPromotionRefused {
        marker_stage: recovery_marker_stage_for_audit(marker.stage),
        reason,
        artifacts: vec![
            crate::logging::audit::MatrixRecoveryKeyArtifactLabel::RotationMarker,
            crate::logging::audit::MatrixRecoveryKeyArtifactLabel::CurrentKey,
            crate::logging::audit::MatrixRecoveryKeyArtifactLabel::PendingKey,
        ],
        current_key: recovery_key_state_for_audit(
            current_digest,
            marker.previous_key_sha256.as_deref(),
            marker.key_sha256.as_deref(),
        ),
        pending_key: recovery_key_state_for_audit(
            pending_digest,
            marker.previous_key_sha256.as_deref(),
            marker.key_sha256.as_deref(),
        ),
    }
}

pub(super) struct RecoveryKeyPromotionRefusalContext<'a> {
    current_digest: Option<&'a str>,
    pending_digest: Option<&'a str>,
    marker_path: &'a Path,
    key_path: &'a Path,
    pending_path: &'a Path,
    operator_reason: &'static str,
    state_dir: &'a Path,
}

pub(super) fn refused_recovery_key_promotion_error(
    marker: &RecoveryKeyRotationMarker,
    reason: crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason,
    context: RecoveryKeyPromotionRefusalContext<'_>,
) -> MatrixError {
    // SECURITY: durable audit. This refusal aborts an interrupted
    // recovery-key rotation at startup. Lossy `audit::audit()` could
    // drop the event under audit-channel saturation, leaving no
    // forensic record of *why* the daemon refused to promote a
    // pending key. Promote to `audit_durable_for_state_dir` per the
    // B80 pattern for irreversible refusals.
    if let Err(audit_err) = crate::logging::audit::audit_durable_for_state_dir(
        context.state_dir.to_path_buf(),
        recovery_pending_refusal_event(
            marker,
            reason,
            context.current_digest,
            context.pending_digest,
        ),
    ) {
        tracing::warn!(
            error = %audit_err,
            "failed to write matrix_recovery_key_pending_promotion_refused audit event; tracing-warn is the only forensic signal"
        );
    }
    warn!(
        audit_event = "matrix_recovery_key_pending_promotion_refused",
        marker_path = %context.marker_path.display(),
        key_path = %context.key_path.display(),
        pending_path = %context.pending_path.display(),
        marker_stage = ?marker.stage,
        operator_reason = context.operator_reason,
        "refusing to promote pending Matrix recovery key"
    );
    recovery_state_io_failed(format!(
        "Matrix recovery-key rotation marker at {} could not prove pending key ownership: {}. \
         Refusing to promote pending key at {} over current key at {}. Remove stale recovery_key.rotating \
         and recovery_key.pending only after confirming the current key is correct.",
        context.marker_path.display(),
        context.operator_reason,
        context.pending_path.display(),
        context.key_path.display()
    ))
}

pub(super) async fn recover_interrupted_recovery_key_rotation(
    state_dir: &Path,
) -> Result<(), MatrixError> {
    inspect_matrix_recovery_cleanup_journal(state_dir).await?;
    let marker_path = matrix_recovery_rotating_marker_path(state_dir);
    if !recovery_artifact_exists(&marker_path, "Matrix recovery rotation marker").await? {
        return Ok(());
    }
    let marker = load_recovery_rotation_marker(&marker_path, state_dir).await?;
    let pending_path = matrix_recovery_pending_key_path(state_dir);
    let key_path = matrix_recovery_key_path(state_dir);
    if recovery_artifact_exists(&pending_path, "Matrix recovery pending key").await? {
        let current_digest = recovery_key_file_sha256(&key_path).await?;
        let pending_digest = recovery_key_file_sha256(&pending_path).await?;
        let refusal_error =
            |reason: crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason,
             current_digest: Option<&str>,
             pending_digest: Option<&str>,
             operator_reason: &'static str| {
                refused_recovery_key_promotion_error(
                    &marker,
                    reason,
                    RecoveryKeyPromotionRefusalContext {
                        current_digest,
                        pending_digest,
                        marker_path: &marker_path,
                        key_path: &key_path,
                        pending_path: &pending_path,
                        operator_reason,
                        state_dir,
                    },
                )
            };
        let Some(pending_digest_value) = pending_digest.as_deref() else {
            return Err(refusal_error(
                crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::PendingKeyMissing,
                current_digest.as_deref(),
                None,
                "pending key disappeared during recovery",
            ));
        };

        match marker.stage {
            RecoveryKeyRotationMarkerStage::Started => {
                if marker.previous_key_sha256.is_none() {
                    let reason = if marker.legacy_text_marker {
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::LegacyMarkerMissingPreviousKeyDigest
                    } else {
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::MissingPreviousKeyDigest
                    };
                    return Err(refusal_error(
                        reason,
                        current_digest.as_deref(),
                        Some(pending_digest_value),
                        "started-stage marker does not record the previous local key digest",
                    ));
                }
                if current_digest.is_none() {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::CurrentKeyMissing,
                        None,
                        Some(pending_digest_value),
                        "current key is missing and the started-stage marker has no new-key digest binding",
                    ));
                }
                return Err(refusal_error(
                    crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::UnboundStartedPending,
                    current_digest.as_deref(),
                    Some(pending_digest_value),
                    "started-stage marker never recorded a new pending key digest",
                ));
            }
            RecoveryKeyRotationMarkerStage::PendingKeyWritten => {
                let Some(expected_digest) = marker.key_sha256.as_deref() else {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::MissingNewKeyDigest,
                        current_digest.as_deref(),
                        Some(pending_digest_value),
                        "marker does not record the new pending key digest",
                    ));
                };
                if !crate::auth::timing_safe_eq(pending_digest_value, expected_digest) {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::PendingKeyDigestMismatch,
                        current_digest.as_deref(),
                        Some(pending_digest_value),
                        "pending key no longer matches the key recorded by the marker",
                    ));
                }
                if current_digest
                    .as_deref()
                    .is_some_and(|c| crate::auth::timing_safe_eq(c, expected_digest))
                {
                    remove_recovery_artifact_with_log(&pending_path, "pending key").await?;
                    remove_recovery_marker_with_log(&marker_path).await?;
                    warn!(
                        audit_event = "matrix_recovery_key_rotate_recovered",
                        path = %key_path.display(),
                        "cleared stale pending Matrix recovery key after final key replacement"
                    );
                    emit_recovery_rotate_recovered_audit(
                        state_dir,
                        crate::logging::audit::MatrixRecoveryKeyRotationStage::PendingKeyWritten,
                        crate::logging::audit::MatrixRecoveryKeyRotateRecoveredOutcome::ClearedStalePending,
                    );
                    return Ok(());
                }
                let Some(current_digest) = current_digest.as_deref() else {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::CurrentKeyMissing,
                        None,
                        Some(pending_digest_value),
                        "pending-stage marker cannot prove the previous local key because the current key is missing",
                    ));
                };
                let Some(previous_digest) = marker.previous_key_sha256.as_deref() else {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::MissingPreviousKeyDigest,
                        Some(current_digest),
                        Some(pending_digest_value),
                        "marker cannot prove the current key is the pre-rotation key",
                    ));
                };
                if !crate::auth::timing_safe_eq(current_digest, previous_digest) {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::CurrentKeyMismatch,
                        Some(current_digest),
                        Some(pending_digest_value),
                        "current key is neither the pre-rotation key nor the new pending key",
                    ));
                }
            }
            RecoveryKeyRotationMarkerStage::FinalKeyReplaced => {
                let Some(expected_digest) = marker.key_sha256.as_deref() else {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::MissingNewKeyDigest,
                        current_digest.as_deref(),
                        Some(pending_digest_value),
                        "final-stage marker does not record the new key digest",
                    ));
                };
                if current_digest
                    .as_deref()
                    .is_some_and(|c| crate::auth::timing_safe_eq(c, expected_digest))
                {
                    remove_recovery_artifact_with_log(&pending_path, "pending key").await?;
                    remove_recovery_marker_with_log(&marker_path).await?;
                    warn!(
                        audit_event = "matrix_recovery_key_rotate_recovered",
                        path = %key_path.display(),
                        "cleared stale pending Matrix recovery key after final key replacement"
                    );
                    emit_recovery_rotate_recovered_audit(
                        state_dir,
                        crate::logging::audit::MatrixRecoveryKeyRotationStage::FinalKeyReplaced,
                        crate::logging::audit::MatrixRecoveryKeyRotateRecoveredOutcome::ClearedStalePending,
                    );
                    return Ok(());
                }
                if current_digest.is_none() {
                    return Err(refusal_error(
                        crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::CurrentKeyMissing,
                        None,
                        Some(pending_digest_value),
                        "final-stage marker recorded key replacement but the current key is missing",
                    ));
                }
                return Err(refusal_error(
                    crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::FinalStagePendingPresent,
                    current_digest.as_deref(),
                    Some(pending_digest_value),
                    "final-stage marker recorded key replacement but pending key is still present and current key does not match the recorded new key",
                ));
            }
        }
        // `pending_digest_value` is the digest the recovery flow
        // computed from `pending_path` via
        // `recovery_key_file_sha256(&pending_path)` a few hundred
        // lines up. Threading it through the helper's pre-rename
        // re-hash check refuses to promote a pending key whose bytes
        // changed between the validation read and this rename.
        replace_owner_only_secret_file(&pending_path, &key_path, pending_digest_value)
            .await
            .map_err(|err| {
                recovery_state_io_failed(format!(
                    "Matrix recovery-key rotation was interrupted with a preserved pending key at {}, \
                     but promoting it to {} failed: {err}",
                    pending_path.display(),
                    key_path.display()
                ))
            })?;
        remove_recovery_marker_with_log(&marker_path).await?;
        warn!(
            audit_event = "matrix_recovery_key_rotate_recovered",
            path = %key_path.display(),
            "promoted pending Matrix recovery key from interrupted rotation"
        );
        emit_recovery_rotate_recovered_audit(
            state_dir,
            recovery_marker_stage_for_audit(marker.stage),
            crate::logging::audit::MatrixRecoveryKeyRotateRecoveredOutcome::PromotedPending,
        );
        return Ok(());
    }
    if matches!(
        marker.stage,
        RecoveryKeyRotationMarkerStage::PendingKeyWritten
            | RecoveryKeyRotationMarkerStage::FinalKeyReplaced
    ) {
        let expected_digest = marker.key_sha256.as_deref().ok_or_else(|| {
            recovery_state_io_failed(format!(
                "Matrix recovery-key rotation marker at {} recorded key replacement without a key digest",
                marker_path.display()
            ))
        })?;
        let final_digest = recovery_key_file_sha256(&key_path).await?;
        if final_digest
            .as_deref()
            .is_some_and(|c| crate::auth::timing_safe_eq(c, expected_digest))
        {
            remove_recovery_marker_with_log(&marker_path).await?;
            warn!(
                audit_event = "matrix_recovery_key_rotate_recovered",
                path = %key_path.display(),
                "cleared completed Matrix recovery-key rotation marker after final key replacement"
            );
            emit_recovery_rotate_recovered_audit(
                state_dir,
                recovery_marker_stage_for_audit(marker.stage),
                crate::logging::audit::MatrixRecoveryKeyRotateRecoveredOutcome::ClearedFinalMarker,
            );
            return Ok(());
        }
    }
    if marker.stage == RecoveryKeyRotationMarkerStage::Started {
        let current_digest = recovery_key_file_sha256(&key_path).await?;
        let prev_eq_current = match (
            marker.previous_key_sha256.as_deref(),
            current_digest.as_deref(),
        ) {
            (Some(p), Some(c)) => crate::auth::timing_safe_eq(p, c),
            _ => false,
        };
        if prev_eq_current {
            remove_recovery_marker_with_log(&marker_path).await?;
            warn!(
                audit_event = "matrix_recovery_key_rotate_recovered",
                path = %key_path.display(),
                "cleared started Matrix recovery-key rotation marker after restore left no pending key"
            );
            emit_recovery_rotate_recovered_audit(
                state_dir,
                crate::logging::audit::MatrixRecoveryKeyRotationStage::Started,
                crate::logging::audit::MatrixRecoveryKeyRotateRecoveredOutcome::ClearedStartedMarker,
            );
            return Ok(());
        }
        return Err(refused_recovery_key_promotion_error(
            &marker,
            crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::PendingKeyMissing,
            RecoveryKeyPromotionRefusalContext {
                current_digest: current_digest.as_deref(),
                pending_digest: None,
                marker_path: &marker_path,
                key_path: &key_path,
                pending_path: &pending_path,
                operator_reason: "started-stage marker exists but no pending key was preserved",
                state_dir,
            },
        ));
    }
    Err(recovery_state_io_failed(format!(
        "Matrix recovery-key rotation marker exists at {} but no pending key was preserved. \
         Rotation outcome is unknown; verify the current key in Element, restore it locally if \
         needed, then remove the marker before retrying rotation.",
        marker_path.display()
    )))
}

/// Recovery cleanup journal is a small JSON (version + phase +
/// per-artifact list). Cap at 16 KiB to cover any plausible
/// artifact list while preventing same-uid OOM from symlink swap.
pub(super) const MATRIX_RECOVERY_CLEANUP_JOURNAL_MAX_BYTES: u64 = 16 * 1024;

pub(super) async fn inspect_matrix_recovery_cleanup_journal(
    state_dir: &Path,
) -> Result<(), MatrixError> {
    let journal_path = matrix_recovery_cleanup_journal_path(state_dir);
    let content = match read_capped_marker_or_journal(
        journal_path.clone(),
        MATRIX_RECOVERY_CLEANUP_JOURNAL_MAX_BYTES,
    )
    .await
    {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(recovery_state_io_failed(format!(
                "failed to read Matrix recovery-key cleanup journal at {}: {err}",
                journal_path.display()
            )));
        }
    };
    let journal: MatrixRecoveryCleanupJournal =
        serde_json::from_slice(content.trim_ascii()).map_err(|err| {
            recovery_state_io_failed(format!(
                "Matrix recovery-key cleanup journal at {} is corrupt: {err}. \
                 Refusing startup repair until recovery_key.cleanup and recovery-key artifacts are inspected.",
                journal_path.display()
            ))
        })?;
    if journal.version != MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION {
        // Defense-in-depth: refuse to act on a journal whose
        // artifact-role semantics may have changed. See the doc on
        // MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION for the downgrade
        // contract — auto-tolerating an unknown version risks
        // skipping artifacts the older binary doesn't recognize and
        // leaving key material on disk under unverified provenance.
        let observed = journal.version;
        let expected = MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION;
        // SECURITY: durable audit — startup-cleanup refusals abort
        // recovery-key cleanup at startup, an irreversible decision
        // for that boot. Lossy `audit::audit()` could drop the
        // event under audit-channel saturation. Promote per the
        // B80 pattern for refusal sites.
        if let Err(audit_err) = crate::logging::audit::audit_durable_for_state_dir(
            state_dir.to_path_buf(),
            crate::logging::audit::AuditEvent::MatrixRecoveryKeyStartupCleanupRefused {
                artifact_count: journal.artifacts.len(),
            },
        ) {
            tracing::warn!(
                error = %audit_err,
                "failed to write matrix_recovery_key_startup_cleanup_refused audit event (version mismatch); tracing-warn is the only forensic signal"
            );
        }
        return Err(recovery_state_io_failed(format!(
            "Matrix recovery-key cleanup journal at {} has unsupported version {observed}; expected {expected}. \
             This typically indicates a downgrade after a newer binary wrote the journal. \
             Recovery: either run the newer binary once to let cleanup complete (preferred), \
             or manually inspect matrix/recovery_key.{{pending,minting,rotating}} artifacts and \
             remove them along with this journal file before restarting.",
            journal_path.display(),
        )));
    }
    match journal.phase {
        MatrixRecoveryCleanupJournalPhase::Completed => {
            remove_recovery_artifact_with_log(&journal_path, "cleanup journal").await
        }
        MatrixRecoveryCleanupJournalPhase::Started => {
            // SECURITY: durable audit — refusing startup repair
            // while a restore cleanup journal is in the Started
            // phase is an irreversible decision (the operator
            // must inspect artifacts manually before retry).
            // Promote from lossy audit::audit() per the B80 pattern.
            if let Err(audit_err) = crate::logging::audit::audit_durable_for_state_dir(
                state_dir.to_path_buf(),
                crate::logging::audit::AuditEvent::MatrixRecoveryKeyStartupCleanupRefused {
                    artifact_count: journal.artifacts.len(),
                },
            ) {
                tracing::warn!(
                    error = %audit_err,
                    "failed to write matrix_recovery_key_startup_cleanup_refused audit event (journal-incomplete); tracing-warn is the only forensic signal"
                );
            }
            warn!(
                path = %journal_path.display(),
                artifact_count = journal.artifacts.len(),
                "refusing Matrix recovery startup repair while restore cleanup journal is incomplete"
            );
            Err(recovery_state_io_failed(format!(
                "Matrix recovery-key restore cleanup journal at {} is still started. \
                 Refusing startup repair so pending recovery key material is not trusted without cleanup provenance.",
                journal_path.display()
            )))
        }
    }
}

/// Owner-only secret-file write with atomic semantics.
///
/// Earlier versions wrote directly to the final path with `create_new`,
/// which leaves a partial/empty file on disk if `write_all` or
/// `sync_all` fails midway. A subsequent startup short-circuits
/// `maybe_enable_recovery` (because `path.exists()` is true) but
/// `maybe_restore_recovery_key` then fails reading the partial content,
/// bricking the daemon until manual cleanup. This implementation
/// instead writes a temp file in the same directory, fsyncs, and only
/// then renames into place — so the final path either holds the
/// complete content or doesn't exist.
///
/// Refuses to overwrite a pre-existing file at the final path
/// (matching the prior `create_new` contract). On Unix, finalization
/// uses `link(2)` from the fully-synced temp file to the final path so
/// the kernel performs create-if-absent atomically; `rename(2)` would
/// replace the destination.
pub(super) async fn recovery_secret_path_exists(
    path: &Path,
    label: &'static str,
) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("inspect {label} at {}: {err}", path.display())),
    }
}

#[cfg(unix)]
pub(super) async fn write_owner_only_secret_file(path: &Path, content: &str) -> Result<(), String> {
    use std::io::Write;

    if recovery_secret_path_exists(path, "secret file").await? {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| err.to_string())?;
    }
    let path = path.to_path_buf();
    // Wrap the spawn_blocking-side clone in Zeroizing so the worker
    // thread's heap copy of the secret payload is wiped on drop. The
    // caller may pass a Zeroizing<String> via &str deref, but that
    // wrapper protects only the caller's copy — `to_string()` here
    // produces a fresh allocation that needs its own zeroize.
    let content = zeroize::Zeroizing::new(content.to_string());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let tmp_path = secret_file_temp_path(&path);
        {
            // Route through the canonical helper for O_NOFOLLOW + O_EXCL +
            // 0o600. Defense-in-depth: O_EXCL alone refuses a symlink-
            // planted tmp today; O_NOFOLLOW guards against a future
            // refactor that weakens create_new and reopens the
            // follow-the-symlink class.
            let mut file = crate::paths::create_atomic_tmp_owner_only(&tmp_path)
                .map_err(|err| format!("create temp secret file: {err}"))?;
            let write_result = file
                .write_all(content.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all());
            if let Err(err) = write_result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("write temp secret file: {err}"));
            }
        }
        if let Err(err) = link_secret_file_no_replace(&tmp_path, &path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        let _ = std::fs::remove_file(&tmp_path);
        // Fsync the parent dir via the shared helper so the linked
        // final path is durable across power-loss. Without this, the
        // kernel may have written the temp file's contents to disk
        // but not yet flushed the dirent change; a crash here loses
        // the final link and the operator boots with the SDK store
        // referencing a server-side recovery secret that has no
        // local key file. Errors propagate now (previously swallowed).
        crate::paths::sync_parent_dir_blocking(&path)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

pub(super) fn link_secret_file_no_replace(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::hard_link(src, dst).map_err(|err| {
        match std::fs::symlink_metadata(dst) {
            Ok(_) => format!(
                    "secret file at {} appeared concurrently; refusing to overwrite",
                    dst.display()
                ),
            Err(inspect_err) if inspect_err.kind() == std::io::ErrorKind::NotFound => {
                format!("link secret file into place: {err}")
            }
            Err(inspect_err) => format!(
                "link secret file into place: {err}; additionally failed to inspect destination {}: {inspect_err}",
                dst.display()
            ),
        }
    })
}

pub(super) async fn promote_owner_only_secret_file(src: &Path, dst: &Path) -> Result<(), String> {
    // SECURITY: same atomic-no-replace contract as
    // `promote_owner_only_cli_secret_no_replace` in cli/mod.rs. The
    // previous Windows branch used `dst.exists()` + `std::fs::rename`,
    // which silently replaces under `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`.
    // `link_secret_file_no_replace` uses `std::fs::hard_link` which is
    // portable across Unix and Windows (NTFS) and atomically refuses
    // an existing destination via EEXIST / ERROR_ALREADY_EXISTS.
    if recovery_secret_path_exists(dst, "secret file").await? {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            dst.display()
        ));
    }
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        link_secret_file_no_replace(&src, &dst)?;
        crate::paths::sync_parent_dir_blocking(&dst)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        std::fs::remove_file(&src).map_err(|err| format!("remove pending secret file: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

pub(super) async fn replace_owner_only_secret_file(
    src: &Path,
    dst: &Path,
    expected_src_digest: &str,
) -> Result<(), String> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    let expected_src_digest = expected_src_digest.to_string();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        // SECURITY: the caller already hashed the source file at a
        // prior path resolution and validated it against the rotation
        // marker. Between that hash and this rename, a same-uid
        // attacker with write access to the parent directory could
        // swap the source dirent for a different file — `rename` then
        // commits attacker bytes to the destination because rename
        // operates on the path, not the FD the caller hashed from.
        //
        // Re-open + re-hash here, just before the rename, narrows the
        // window to a few microseconds within this same blocking
        // task. This is NOT bulletproof — `renameat2` with
        // `RENAME_EXCHANGE` or `linkat` from `/proc/self/fd` would
        // anchor on the FD's inode, but neither is portable across
        // Unix variants Carapace supports — so we accept the narrow
        // residual window as defense-in-depth, on top of the parent
        // directory being chmod 0o700 owner-only.
        use std::io::Read;
        let mut src_file = crate::paths::open_regular_file_no_hang_no_follow(&src)
            .map_err(|err| {
                format!("open src secret file for pre-rename digest verification: {err}")
            })?
            .ok_or_else(|| {
                "src secret file disappeared before pre-rename digest verification".to_string()
            })?;
        // SECURITY: pre-allocate `MATRIX_RECOVERY_KEY_FILE_MAX_BYTES + 1`
        // capacity in a single up-front allocation so `read_to_end`'s
        // growth loop NEVER reallocates. The previous `Vec::new()`
        // started at zero capacity; `read_to_end` then grew via doubling
        // (typical 0 → 32 → 64 → ... → 8192), and each realloc COPIED
        // the partially-read recovery-key bytes into a fresh allocation
        // and FREED the previous slot without zeroing it. `Zeroizing`
        // only wipes the final live allocation on Drop; the intermediate
        // generations sit in glibc/jemalloc freelists with plaintext
        // until a future alloc reuses the slot. Single-allocation
        // pre-reserve makes the buffer round-trip zeroize-clean.
        let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(
            (MATRIX_RECOVERY_KEY_FILE_MAX_BYTES + 1) as usize,
        ));
        (&mut src_file)
            .take(MATRIX_RECOVERY_KEY_FILE_MAX_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|err| format!("read src secret file for digest verification: {err}"))?;
        if buf.len() as u64 > MATRIX_RECOVERY_KEY_FILE_MAX_BYTES {
            return Err(format!(
                "src secret file exceeds {} byte cap during digest verification",
                MATRIX_RECOVERY_KEY_FILE_MAX_BYTES
            ));
        }
        // The caller's digest was computed against `recovery_key_sha256`
        // which trims and hashes ASCII; re-hash the same shape against
        // the borrowed &str view of `buf`. `from_utf8` (slice variant)
        // does NOT clone the bytes — it only validates the UTF-8
        // structure and returns a &str view, so no additional
        // un-zeroized allocation is created. recovery_key_sha256
        // internally calls `.trim().as_bytes()` then `Sha256::update`,
        // so the digest never copies the plaintext into a fresh String.
        let content = std::str::from_utf8(&buf).map_err(|err| {
            format!("src secret file is not UTF-8 during digest verification: {err}")
        })?;
        let actual_digest = recovery_key_sha256(content);
        if !crate::auth::timing_safe_eq(&actual_digest, &expected_src_digest) {
            return Err(format!(
                "src secret file digest changed between caller's validation and rename: \
                 expected {expected_src_digest}, observed {actual_digest}; \
                 refusing rename — a same-uid attacker may have swapped the dirent. \
                 Re-run the recovery flow after confirming no other process is writing this path."
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600))
                .map_err(|err| format!("set pending secret mode: {err}"))?;
        }
        std::fs::rename(&src, &dst).map_err(|err| {
            format!(
                "replace secret file {} from {}: {err}",
                dst.display(),
                src.display()
            )
        })?;
        crate::paths::sync_parent_dir_blocking(&dst)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

#[cfg(not(unix))]
pub(super) async fn write_owner_only_secret_file(path: &Path, content: &str) -> Result<(), String> {
    if recovery_secret_path_exists(path, "secret file").await? {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| err.to_string())?;
    }
    let path = path.to_path_buf();
    // Same Zeroize discipline as the unix branch — see comment there.
    let content = zeroize::Zeroizing::new(content.to_string());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write;
        let tmp_path = secret_file_temp_path(&path);
        {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|err| format!("create temp secret file: {err}"))?;
            let write_result = file
                .write_all(content.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all());
            if let Err(err) = write_result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("write temp secret file: {err}"));
            }
        }
        // SECURITY: same atomic-no-replace contract as the Unix
        // branch. `path.exists()` + `std::fs::rename` is TOCTOU-prone
        // on Windows because std-fs-rename maps to
        // `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` and silently
        // overwrites concurrent writers. `link_secret_file_no_replace`
        // is portable (NTFS supports hard links) and atomically
        // refuses an existing destination.
        let link_result = link_secret_file_no_replace(&tmp_path, &path);
        let _ = std::fs::remove_file(&tmp_path);
        if let Err(err) = link_result {
            return Err(err);
        }
        // Fsync the parent dir via the shared helper. On Windows the
        // helper is a no-op (NTFS journal handles dirent durability);
        // on Unix it surfaces fsync failures as Err.
        crate::paths::sync_parent_dir_blocking(&path)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

pub(super) fn secret_file_temp_path(path: &Path) -> PathBuf {
    crate::paths::atomic_tmp_path(path, "secret")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_sha256_hasher_zeroizes_on_drop_for_recovery_digests() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroizes_on_drop::<Sha256>();
    }

    /// Pin the cap edge: a file at exactly `MATRIX_RECOVERY_KEY_FILE_MAX_BYTES`
    /// bytes must succeed; a file at cap + 1 must be refused with the
    /// "exceeds N bytes" error AND no path disclosure. Prevents an
    /// off-by-one in the post-read `buf.len() > cap` check that would
    /// either reject the cap-boundary case or accept one byte over.
    #[tokio::test(flavor = "current_thread")]
    async fn test_read_recovery_key_file_to_string_bounded_at_cap_edges() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("matrix");
        std::fs::create_dir_all(&dir).expect("create matrix dir");

        // At cap: succeed.
        let at_cap = dir.join("recovery_key.at_cap");
        std::fs::write(
            &at_cap,
            vec![b'x'; MATRIX_RECOVERY_KEY_FILE_MAX_BYTES as usize],
        )
        .expect("write at-cap file");
        let result =
            read_recovery_key_file_to_string_bounded(&at_cap, "Matrix recovery key digest")
                .await
                .expect("at-cap read should not error");
        let bytes = result.expect("at-cap file should yield Some");
        assert_eq!(bytes.len(), MATRIX_RECOVERY_KEY_FILE_MAX_BYTES as usize);

        // At cap + 1: refuse.
        let over_cap = dir.join("recovery_key.over_cap");
        std::fs::write(
            &over_cap,
            vec![b'x'; (MATRIX_RECOVERY_KEY_FILE_MAX_BYTES + 1) as usize],
        )
        .expect("write over-cap file");
        let err = read_recovery_key_file_to_string_bounded(&over_cap, "Matrix recovery key digest")
            .await
            .expect_err("over-cap read should fail");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "exceeds {} bytes",
                MATRIX_RECOVERY_KEY_FILE_MAX_BYTES
            )),
            "over-cap error must surface the cap value: {msg}"
        );
        assert!(
            !msg.contains(&over_cap.display().to_string()),
            "over-cap error must not expose artifact path: {msg}"
        );
    }

    /// Pin the missing-file case: a NotFound returns Ok(None), not Err.
    /// The daemon's startup probe and rekey recovery rely on this to
    /// distinguish "no key on disk yet" from "key read failed".
    #[tokio::test(flavor = "current_thread")]
    async fn test_read_recovery_key_file_to_string_bounded_missing_returns_none() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("matrix").join("recovery_key.missing");
        let result =
            read_recovery_key_file_to_string_bounded(&missing, "Matrix recovery key digest")
                .await
                .expect("missing-file read should not error");
        assert!(result.is_none(), "missing file must yield None");
    }

    /// Pin the empty-file case: a 0-byte file returns Some("") which
    /// the caller (`maybe_restore_recovery_key`) treats as "empty
    /// after trim" → fail-closed with the operator-actionable
    /// "recovery key missing" error rather than passing empty bytes
    /// to the SDK.
    #[tokio::test(flavor = "current_thread")]
    async fn test_read_recovery_key_file_to_string_bounded_empty_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("matrix");
        std::fs::create_dir_all(&dir).expect("create matrix dir");
        let empty = dir.join("recovery_key.empty");
        std::fs::write(&empty, b"").expect("write empty file");

        let result = read_recovery_key_file_to_string_bounded(&empty, "Matrix recovery key digest")
            .await
            .expect("empty-file read should not error");
        let bytes = result.expect("empty file should yield Some");
        assert!(bytes.is_empty(), "empty file should yield empty string");
    }

    /// Pin the non-regular-file refusal: a directory at the path
    /// must fail with the "not a regular file" error AND not expose
    /// the path. Companion to `test_recovery_key_digest_read_errors_do_not_expose_paths`
    /// which exercises the path-disclosure-prevention specifically.
    #[tokio::test(flavor = "current_thread")]
    async fn test_read_recovery_key_file_to_string_bounded_refuses_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir_at_key_path = temp.path().join("matrix").join("recovery_key.dir");
        std::fs::create_dir_all(&dir_at_key_path).expect("create dir at key path");

        let err = read_recovery_key_file_to_string_bounded(
            &dir_at_key_path,
            "Matrix recovery key digest",
        )
        .await
        .expect_err("directory read should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("not a regular file"),
            "directory error must mention non-regular-file: {msg}"
        );
        assert!(
            !msg.contains(&dir_at_key_path.display().to_string()),
            "directory error must not expose artifact path: {msg}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recovery_key_digest_read_errors_do_not_expose_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("matrix").join("recovery_key");
        std::fs::create_dir_all(&path).expect("create directory at key path");

        let err = recovery_key_file_sha256(&path)
            .await
            .expect_err("directory read should fail");

        let message = err.to_string();
        assert!(message.contains("failed to read Matrix recovery key digest"));
        assert!(
            !message.contains(&path.display().to_string()),
            "recovery-key digest errors must not expose artifact paths: {message}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recovery_key_file_has_secret_bytes_for_nonempty_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recovery_key");
        std::fs::write(&path, b"EsT8 Pgxc Fake Recovery Key\n").expect("write");
        assert!(recovery_key_file_has_secret_bytes(&path)
            .await
            .expect("probe must succeed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recovery_key_file_has_secret_bytes_for_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recovery_key");
        std::fs::write(&path, b"").expect("write zero-byte");
        assert!(
            !recovery_key_file_has_secret_bytes(&path)
                .await
                .expect("probe must succeed"),
            "zero-byte recovery key file must not count as having secret bytes — \
             the stale-marker cleanup branch must keep the marker for operator inspection"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recovery_key_file_has_secret_bytes_for_whitespace_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recovery_key");
        std::fs::write(&path, b"   \n\t\r\n").expect("write whitespace");
        assert!(
            !recovery_key_file_has_secret_bytes(&path)
                .await
                .expect("probe must succeed"),
            "whitespace-only recovery key file must not count as having secret bytes"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cleanup_stale_recovery_minting_marker_removes_marker_when_key_has_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("recovery_key");
        let marker_path = dir.path().join("recovery_key.minting");
        std::fs::write(&key_path, b"EsT8 Pgxc Fake Recovery Key\n").expect("write key");
        std::fs::write(&marker_path, b"recovery-minting-in-progress\n").expect("write marker");

        cleanup_stale_recovery_minting_marker(&key_path, &marker_path).await;

        assert!(!marker_path.exists(), "marker should have been cleaned up");
        assert!(key_path.exists(), "key file must remain untouched");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cleanup_stale_recovery_minting_marker_preserves_marker_when_key_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("recovery_key");
        let marker_path = dir.path().join("recovery_key.minting");
        std::fs::write(&key_path, b"").expect("write zero-byte key");
        std::fs::write(&marker_path, b"recovery-minting-in-progress\n").expect("write marker");

        cleanup_stale_recovery_minting_marker(&key_path, &marker_path).await;

        assert!(
            marker_path.exists(),
            "marker MUST survive an empty key file — it is the only breadcrumb to the \
             orphaned server-side mint and dropping it would strand the recovery state"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cleanup_stale_recovery_minting_marker_is_infallible_when_key_unreadable() {
        // Even if the key probe errors (e.g., transient I/O issue,
        // missing path), the cleanup must not panic or propagate a
        // failure — a healthy daemon must not refuse startup just
        // because a stale marker happens to be unverifiable.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("recovery_key");
        let marker_path = dir.path().join("recovery_key.minting");
        // Deliberately do NOT create key_path so the probe surfaces a
        // typed I/O error.
        std::fs::write(&marker_path, b"recovery-minting-in-progress\n").expect("write marker");

        cleanup_stale_recovery_minting_marker(&key_path, &marker_path).await;

        // The marker should remain — we don't take destructive action
        // when we cannot confirm the key file's contents.
        assert!(marker_path.exists(), "marker MUST survive a probe error");
    }

    #[test]
    fn test_recovery_key_rotation_marker_json_wire_shape_is_pinned() {
        let marker = RecoveryKeyRotationMarker {
            stage: RecoveryKeyRotationMarkerStage::PendingKeyWritten,
            key_sha256: Some("new-digest".to_string()),
            previous_key_sha256: Some("previous-digest".to_string()),
            updated_at_ms: 1234,
            legacy_text_marker: false,
        };

        let value = serde_json::to_value(&marker).unwrap();
        assert_eq!(value["stage"], "pending_key_written");
        assert_eq!(value["keySha256"], "new-digest");
        assert_eq!(value["previousKeySha256"], "previous-digest");
        assert_eq!(value["updatedAtMs"], 1234);
        assert!(
            value.get("legacyTextMarker").is_none(),
            "in-memory legacy sentinel must not leak into persisted marker JSON"
        );

        let legacy_json = serde_json::json!({
            "stage": "pending_key_written",
            "keySha256": "new-digest",
            "updatedAtMs": 1234
        });
        let parsed: RecoveryKeyRotationMarker = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(
            parsed.stage,
            RecoveryKeyRotationMarkerStage::PendingKeyWritten
        );
        assert_eq!(parsed.key_sha256.as_deref(), Some("new-digest"));
        assert_eq!(parsed.previous_key_sha256, None);
        assert!(
            !parsed.legacy_text_marker,
            "typed JSON marker missing previousKeySha256 is not the legacy text sentinel"
        );
    }

    #[test]
    fn test_recovery_key_pending_refusal_audit_payload_is_typed_and_redacted() {
        let marker = RecoveryKeyRotationMarker {
            stage: RecoveryKeyRotationMarkerStage::FinalKeyReplaced,
            key_sha256: Some("new-digest-secret".to_string()),
            previous_key_sha256: Some("old-digest-secret".to_string()),
            updated_at_ms: 1234,
            legacy_text_marker: false,
        };

        let event = recovery_pending_refusal_event(
            &marker,
            crate::logging::audit::MatrixRecoveryKeyPromotionRefusalReason::FinalStagePendingPresent,
            Some("old-digest-secret"),
            Some("pending-digest-secret"),
        );
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(
            value["type"],
            serde_json::json!("matrix_recovery_key_pending_promotion_refused")
        );
        assert_eq!(value["marker_stage"], "final_key_replaced");
        assert_eq!(value["reason"], "final_stage_pending_present");
        assert_eq!(value["current_key"], "matches_previous_key");
        assert_eq!(value["pending_key"], "mismatch");
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains("digest-secret"));
        assert!(!serialized.contains("recovery_key.pending"));
        assert!(!serialized.contains("recovery_key.rotating"));
        assert!(!serialized.contains('/'));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recover_interrupted_recovery_key_rotation_clears_completed_marker() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let key = "recovery-key-after-rotation";
        std::fs::write(&key_path, format!("{key}\n")).expect("write final key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::FinalKeyReplaced,
            Some(recovery_key_sha256(key)),
            Some(recovery_key_sha256("recovery-key-before-rotation")),
        )
        .await
        .expect("write completed marker");

        recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect("completed marker should be cleared");

        assert!(
            !marker_path.exists(),
            "post-replacement recovery-key rotation marker should be removed"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{key}\n")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_started_recovery_key_rotation_without_pending_clears_when_current_matches_marker()
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let restored_key = "operator-restored-previous-key";
        std::fs::write(&key_path, format!("{restored_key}\n")).expect("write restored key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::Started,
            None,
            Some(recovery_key_sha256(restored_key)),
        )
        .await
        .expect("write started marker");

        recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect("started marker with no pending key and matching current key should clear");

        assert!(
            !marker_path.exists(),
            "restore cleanup crash marker should be cleared"
        );
        assert!(
            !pending_path.exists(),
            "restore cleanup crash state must not recreate pending key"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{restored_key}\n")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recover_interrupted_recovery_key_rotation_refuses_started_cleanup_journal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let journal_path = matrix_recovery_cleanup_journal_path(temp.path());
        std::fs::create_dir_all(pending_path.parent().unwrap()).expect("create matrix dir");
        std::fs::write(&pending_path, "pending-recovery-secret\n").expect("write pending key");
        let journal = MatrixRecoveryCleanupJournal {
            version: MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION,
            phase: MatrixRecoveryCleanupJournalPhase::Started,
            artifacts: vec![MatrixRecoveryCleanupJournalArtifact {
                role: MatrixRecoveryCleanupArtifactRole::PendingKey,
                path: "matrix/recovery_key.pending".to_string(),
                expected_provenance: "stale_after_operator_restore".to_string(),
                result: MatrixRecoveryCleanupArtifactResult {
                    state: MatrixRecoveryCleanupArtifactResultState::Pending,
                    error_kind: None,
                },
            }],
        };
        std::fs::write(&journal_path, serde_json::to_vec(&journal).unwrap())
            .expect("write cleanup journal");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("started cleanup journal must fail closed");

        assert!(
            err.to_string().contains("cleanup journal"),
            "unexpected cleanup journal refusal: {err}"
        );
        assert!(
            pending_path.exists(),
            "startup must not trust or remove pending material from a started cleanup journal"
        );
        assert!(journal_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recover_interrupted_recovery_key_rotation_clears_completed_cleanup_journal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_path = matrix_recovery_cleanup_journal_path(temp.path());
        std::fs::create_dir_all(journal_path.parent().unwrap()).expect("create matrix dir");
        let journal = MatrixRecoveryCleanupJournal {
            version: MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION,
            phase: MatrixRecoveryCleanupJournalPhase::Completed,
            artifacts: vec![MatrixRecoveryCleanupJournalArtifact {
                role: MatrixRecoveryCleanupArtifactRole::PendingKey,
                path: "matrix/recovery_key.pending".to_string(),
                expected_provenance: "stale_after_operator_restore".to_string(),
                result: MatrixRecoveryCleanupArtifactResult {
                    state: MatrixRecoveryCleanupArtifactResultState::Removed,
                    error_kind: None,
                },
            }],
        };
        std::fs::write(&journal_path, serde_json::to_vec(&journal).unwrap())
            .expect("write cleanup journal");

        recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect("completed cleanup journal should be cleared");

        assert!(
            !journal_path.exists(),
            "completed cleanup journal should be removed before startup repair continues"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_load_recovery_rotation_marker_times_out_wedged_read() {
        let marker_path = Path::new("matrix/recovery_key.rotating");
        let state_dir = Path::new(".");
        let err = load_recovery_rotation_marker_with_timeout(
            marker_path,
            state_dir,
            std::time::Duration::ZERO,
            std::future::pending::<std::io::Result<Vec<u8>>>(),
        )
        .await
        .expect_err("wedged marker read must time out");

        assert!(
            err.to_string()
                .contains("timed out reading Matrix recovery-key rotation marker"),
            "unexpected timeout error: {err}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recovery_artifact_cleanup_failure_is_returned() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(&marker_path).expect("create marker directory");

        let err = remove_recovery_marker_with_log(&marker_path)
            .await
            .expect_err("directory marker cleanup must fail");

        assert!(
            err.to_string()
                .contains("failed to remove Matrix recovery marker"),
            "cleanup failure must be operator-visible, got {err}"
        );
        assert!(
            marker_path.exists(),
            "failed cleanup must not report success or hide the artifact"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recover_interrupted_recovery_key_rotation_promotes_pending_over_old_current_key()
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let old_key = "recovery-key-before-rotation";
        let new_key = "recovery-key-after-rotation";
        std::fs::write(&key_path, format!("{old_key}\n")).expect("write old key");
        std::fs::write(&pending_path, format!("{new_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::PendingKeyWritten,
            Some(recovery_key_sha256(new_key)),
            Some(recovery_key_sha256(old_key)),
        )
        .await
        .expect("write pending marker");

        recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect("pending key with stale old current key should recover");

        assert!(
            !marker_path.exists(),
            "stale recovery-key rotation marker should be removed"
        );
        assert!(!pending_path.exists(), "pending key should be promoted");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{new_key}\n")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_pending_key_written_refuses_pending_when_current_key_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let old_key = "recovery-key-before-rotation";
        let new_key = "recovery-key-after-rotation";
        std::fs::write(&pending_path, format!("{new_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::PendingKeyWritten,
            Some(recovery_key_sha256(new_key)),
            Some(recovery_key_sha256(old_key)),
        )
        .await
        .expect("write pending marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("pending-key-written marker must fail closed when current key is missing");

        assert!(
            err.to_string().contains("current key is missing"),
            "unexpected recovery error: {err}"
        );
        assert!(
            marker_path.exists(),
            "marker must remain for operator repair"
        );
        assert!(pending_path.exists(), "pending key must remain untouched");
        assert!(
            !key_path.exists(),
            "missing current key must not be recreated"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_corrupt_typed_recovery_key_rotation_marker_fails_closed_without_leaking_material()
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        std::fs::write(&key_path, "current-recovery-secret\n").expect("write current key");
        std::fs::write(&pending_path, "pending-recovery-secret\n").expect("write pending key");
        std::fs::write(
            &marker_path,
            br#"{"stage":"pending_key_written","keySha256":"#,
        )
        .expect("write corrupt typed marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("corrupt typed marker must fail closed");
        let message = err.to_string();
        let temp_path = temp.path().to_string_lossy().to_string();

        assert!(message.contains("typed recovery-key rotation marker is malformed"));
        assert!(!message.contains(&temp_path));
        assert!(!message.contains("current-recovery-secret"));
        assert!(!message.contains("pending-recovery-secret"));
        assert!(!message.contains("keySha256"));
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            "current-recovery-secret\n"
        );
        assert_eq!(
            std::fs::read_to_string(&pending_path).unwrap(),
            "pending-recovery-secret\n"
        );
        assert!(
            marker_path.exists(),
            "corrupt marker must remain for explicit operator inspection"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_bom_prefixed_typed_recovery_key_rotation_marker_is_corrupt_typed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        std::fs::write(&key_path, "current-recovery-secret\n").expect("write current key");
        std::fs::write(&pending_path, "pending-recovery-secret\n").expect("write pending key");
        std::fs::write(
            &marker_path,
            b"\xEF\xBB\xBF{\"stage\":\"pending_key_written\",\"keySha256\":",
        )
        .expect("write bom-prefixed corrupt typed marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("BOM-prefixed typed marker must fail closed as typed corruption");
        assert!(
            err.to_string()
                .contains("typed recovery-key rotation marker is malformed"),
            "BOM-prefixed typed marker must not be classified as unknown legacy: {err}"
        );
        assert!(
            marker_path.exists(),
            "corrupt marker must remain for explicit operator inspection"
        );
    }

    /// Batch 95: the rename helper for recovery-key promotion must
    /// refuse when the source file's bytes changed between the
    /// caller's validation and our rename. A same-uid attacker who
    /// races the dirent swap should NOT be able to commit unverified
    /// bytes into `recovery_key`.
    #[tokio::test(flavor = "current_thread")]
    async fn test_replace_owner_only_secret_file_refuses_on_digest_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("src");
        let dst = temp.path().join("dst");
        std::fs::write(&src, "expected-bytes\n").expect("write src");
        // Caller's hash (legitimate validation step).
        let expected_digest = recovery_key_sha256("expected-bytes");
        // Simulate a TOCTOU swap: between caller's hash and the
        // rename helper's re-hash, an attacker rewrote the file at
        // `src`.
        std::fs::write(&src, "attacker-bytes\n").expect("swap src bytes");
        let err = replace_owner_only_secret_file(&src, &dst, &expected_digest)
            .await
            .expect_err("helper must refuse rename when source digest changed");
        assert!(
            err.contains("digest changed"),
            "expected digest-mismatch refusal, got: {err}"
        );
        assert!(
            !dst.exists(),
            "rename must not commit attacker bytes when digest mismatch is detected"
        );
        assert!(src.exists(), "src dirent should still be present");
    }

    /// Batch 95 companion: happy path — when the source bytes do
    /// match the expected digest, the rename completes normally.
    #[tokio::test(flavor = "current_thread")]
    async fn test_replace_owner_only_secret_file_succeeds_on_digest_match() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("src");
        let dst = temp.path().join("dst");
        let content = "expected-bytes";
        std::fs::write(&src, format!("{content}\n")).expect("write src");
        let expected_digest = recovery_key_sha256(content);
        replace_owner_only_secret_file(&src, &dst, &expected_digest)
            .await
            .expect("rename must succeed when src digest matches expected");
        assert!(dst.exists(), "rename should have committed dst");
        assert!(!src.exists(), "src should have been moved");
        assert_eq!(
            std::fs::read_to_string(&dst).expect("read dst"),
            format!("{content}\n")
        );
    }

    /// Batch 113: `replace_owner_only_secret_file`'s re-read buffer is
    /// `Zeroizing<Vec<u8>>` with pre-allocated capacity so no realloc
    /// happens during `read_to_end`. Verify the read path produces
    /// the same successful outcome regardless of file size up to the
    /// recovery-key cap. (We can't directly inspect the freed heap
    /// from a unit test, but a regression on the realloc-free
    /// allocation contract would show as a panic / OOM at the cap
    /// boundary — this test exercises that boundary.)
    #[tokio::test(flavor = "current_thread")]
    async fn test_replace_owner_only_secret_file_handles_max_size_no_realloc() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("src");
        let dst = temp.path().join("dst");
        // Fill the source file to exactly the recovery-key cap (4 KiB).
        let max_bytes_usize: usize = MATRIX_RECOVERY_KEY_FILE_MAX_BYTES as usize;
        let content_bytes = vec![b'x'; max_bytes_usize];
        std::fs::write(&src, &content_bytes).expect("write src at cap");
        // recovery_key_sha256 trims; with no trailing whitespace the
        // trimmed and untrimmed forms are equal.
        let content_str = std::str::from_utf8(&content_bytes).unwrap();
        let expected_digest = recovery_key_sha256(content_str);
        replace_owner_only_secret_file(&src, &dst, &expected_digest)
            .await
            .expect("at-cap rename must succeed");
        assert!(dst.exists());
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dst).unwrap(), content_bytes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_started_recovery_key_rotation_refuses_unbound_pending_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let old_key = "recovery-key-before-started-marker";
        let new_key = "recovery-key-pending-after-started-marker";
        std::fs::write(&key_path, format!("{old_key}\n")).expect("write old key");
        std::fs::write(&pending_path, format!("{new_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::Started,
            None,
            Some(recovery_key_sha256(old_key)),
        )
        .await
        .expect("write started marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("started marker must not promote a pending key without a new-key digest");

        assert!(
            err.to_string()
                .contains("started-stage marker never recorded a new pending key digest"),
            "unexpected recovery error: {err}"
        );
        assert!(marker_path.exists());
        assert!(pending_path.exists());
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{old_key}\n")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_started_recovery_key_rotation_refuses_pending_when_current_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(pending_path.parent().unwrap()).expect("create matrix dir");
        let old_key = "recovery-key-before-started-marker";
        let pending_key = "pending-key-after-started-marker";
        std::fs::write(&pending_path, format!("{pending_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::Started,
            None,
            Some(recovery_key_sha256(old_key)),
        )
        .await
        .expect("write started marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("started marker with missing current key must fail closed");

        assert!(
            err.to_string().contains("current key is missing"),
            "unexpected recovery error: {err}"
        );
        assert!(pending_path.exists() && marker_path.exists());
        assert!(!matrix_recovery_key_path(temp.path()).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_recover_interrupted_recovery_key_rotation_refuses_stale_pending_over_restored_key(
    ) {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let restored_key = "operator-restored-current-recovery-key";
        let stale_pending_key = "stale-pending-recovery-key";
        std::fs::write(&key_path, format!("{restored_key}\n")).expect("write restored key");
        std::fs::write(&pending_path, format!("{stale_pending_key}\n"))
            .expect("write stale pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::PendingKeyWritten,
            Some(recovery_key_sha256(stale_pending_key)),
            Some(recovery_key_sha256("previous-rotation-key")),
        )
        .await
        .expect("write stale marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("stale pending key must not overwrite restored current key");

        assert!(
            err.to_string()
                .contains("current key is neither the pre-rotation key nor the new pending key"),
            "unexpected recovery error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{restored_key}\n"),
            "current restored key must remain untouched"
        );
        assert!(
            pending_path.exists() && marker_path.exists(),
            "operator must inspect stale recovery artifacts explicitly"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_final_key_replaced_refuses_pending_over_restored_old_current_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let old_key = "operator-restored-old-recovery-key";
        let new_key = "new-recovery-key-recorded-by-marker";
        std::fs::write(&key_path, format!("{old_key}\n")).expect("write restored old key");
        std::fs::write(&pending_path, format!("{new_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::FinalKeyReplaced,
            Some(recovery_key_sha256(new_key)),
            Some(recovery_key_sha256(old_key)),
        )
        .await
        .expect("write final marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("final-stage marker must never promote pending over restored current key");

        assert!(
            err.to_string()
                .contains("final-stage marker recorded key replacement"),
            "unexpected recovery error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{old_key}\n")
        );
        assert!(pending_path.exists() && marker_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_final_key_replaced_clears_stale_pending_when_current_matches_new_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let old_key = "recovery-key-before-rotation";
        let new_key = "recovery-key-after-rotation";
        std::fs::write(&key_path, format!("{new_key}\n")).expect("write final key");
        std::fs::write(&pending_path, "stale-pending-material\n").expect("write stale pending");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::FinalKeyReplaced,
            Some(recovery_key_sha256(new_key)),
            Some(recovery_key_sha256(old_key)),
        )
        .await
        .expect("write final marker");

        recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect("final-stage marker with current new key should clear stale artifacts");

        assert!(!pending_path.exists());
        assert!(!marker_path.exists());
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{new_key}\n")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_started_recovery_key_rotation_refuses_restored_current_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let previous_key = "previous-recovery-key";
        let restored_key = "operator-restored-recovery-key";
        let pending_key = "pending-recovery-key";
        std::fs::write(&key_path, format!("{restored_key}\n")).expect("write restored key");
        std::fs::write(&pending_path, format!("{pending_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::Started,
            None,
            Some(recovery_key_sha256(previous_key)),
        )
        .await
        .expect("write started marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("started marker must not overwrite restored current key");

        assert!(
            err.to_string()
                .contains("started-stage marker never recorded a new pending key digest"),
            "unexpected recovery error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{restored_key}\n")
        );
        assert!(pending_path.exists() && marker_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_legacy_recovery_key_rotation_marker_refuses_blind_promotion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        std::fs::write(&key_path, "operator-restored\n").expect("write current key");
        std::fs::write(&pending_path, "legacy-pending\n").expect("write pending key");
        std::fs::write(&marker_path, "recovery-rotation-in-progress\n")
            .expect("write legacy marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("legacy digest-less marker must fail closed");

        assert!(
            err.to_string()
                .contains("does not record the previous local key digest"),
            "unexpected recovery error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            "operator-restored\n"
        );
        assert!(pending_path.exists() && marker_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_legacy_recovery_key_rotation_marker_without_current_key_still_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(pending_path.parent().unwrap()).expect("create matrix dir");
        std::fs::write(&pending_path, "legacy-pending\n").expect("write pending key");
        std::fs::write(&marker_path, "recovery-rotation-in-progress\n")
            .expect("write legacy marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("legacy digest-less marker cannot prove pending ownership");

        assert!(
            err.to_string()
                .contains("does not record the previous local key digest"),
            "unexpected recovery error: {err}"
        );
        assert!(pending_path.exists() && marker_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_pending_key_written_refuses_restored_current_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = matrix_recovery_key_path(temp.path());
        let pending_path = matrix_recovery_pending_key_path(temp.path());
        let marker_path = matrix_recovery_rotating_marker_path(temp.path());
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("create matrix dir");
        let previous_key = "previous-recovery-key";
        let restored_key = "operator-restored-current-key";
        let pending_key = "new-pending-key";
        std::fs::write(&key_path, format!("{restored_key}\n")).expect("write restored key");
        std::fs::write(&pending_path, format!("{pending_key}\n")).expect("write pending key");
        write_recovery_rotation_marker_stage_durable(
            &marker_path,
            RecoveryKeyRotationMarkerStage::PendingKeyWritten,
            Some(recovery_key_sha256(pending_key)),
            Some(recovery_key_sha256(previous_key)),
        )
        .await
        .expect("write pending marker");

        let err = recover_interrupted_recovery_key_rotation(temp.path())
            .await
            .expect_err("pending key must not replace restored current mismatch");

        assert!(
            err.to_string()
                .contains("current key is neither the pre-rotation key nor the new pending key"),
            "unexpected recovery error: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{restored_key}\n")
        );
        assert!(pending_path.exists() && marker_path.exists());
    }
}
