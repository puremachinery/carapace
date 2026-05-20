use super::*;
use matrix_sdk::encryption::verification::{SasState, SasVerification, VerificationRequestState};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixVerificationInfo {
    /// Opaque daemon-owned verification id used by the control API.
    pub flow_id: String,
    /// Matrix protocol flow / transaction id, sanitized for safe
    /// rendering in operator UIs and as a stable input to the
    /// `flow_id` derivation. Sanitization strips bidi / zero-width /
    /// Cf-class codepoints so a hostile peer cannot inject ANSI/
    /// scrollback noise into operator dashboards.
    pub protocol_flow_id: String,
    /// Raw bytes of `protocol_flow_id` as supplied by the SDK, used
    /// internally for `client.encryption().get_verification_*`
    /// lookups. Skipped from wire serialization — the sanitized
    /// `protocol_flow_id` above is the one operators reference.
    /// Without this raw form, sanitize-altered flow ids would fail
    /// SDK lookup (sanitize is non-bijective; the SDK indexes by raw
    /// bytes from the original to-device event).
    #[serde(skip)]
    pub raw_protocol_flow_id: String,
    pub user_id: String,
    /// Device id of the peer being verified, or absent when the
    /// protocol flow targets the user without a specific device.
    /// `skip_serializing_if = Option::is_none` matches the convention
    /// on `sas` below: omit-when-absent rather than emit `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub state: MatrixVerificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sas: Option<MatrixSasInfo>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSasInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<Vec<MatrixSasEmoji>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<[u16; 3]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSasEmoji {
    pub symbol: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerificationState {
    Created,
    Requested,
    Ready,
    Transitioned,
    Started,
    Accepted,
    KeysExchanged,
    Confirmed,
    Done,
    Cancelled,
    Mismatched,
}

impl MatrixVerificationState {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, Self::Cancelled | Self::Done | Self::Mismatched)
    }

    /// Snake_case form matching the wire `state` field
    /// (`#[serde(rename_all = "snake_case")]`). Use this when
    /// embedding the state in operator-visible error messages so
    /// `cara matrix verifications` JSON values round-trip-grep
    /// against the error string.
    fn as_wire_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Requested => "requested",
            Self::Ready => "ready",
            Self::Transitioned => "transitioned",
            Self::Started => "started",
            Self::Accepted => "accepted",
            Self::KeysExchanged => "keys_exchanged",
            Self::Confirmed => "confirmed",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
            Self::Mismatched => "mismatched",
        }
    }
}

impl std::fmt::Display for MatrixVerificationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire_str())
    }
}

pub(super) async fn bounded_verification_refresh(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    ws_state: &Arc<WsServerState>,
) -> Result<(), MatrixError> {
    bounded_matrix_result(
        "Matrix verification refresh",
        refresh_verification_records(client, state, ws_state),
    )
    .await
}

pub(super) async fn handle_to_device_event(
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    config: MatrixConfig,
    event: AnyToDeviceEvent,
) {
    let Some((sender, event_kind)) = matrix_to_device_verification_sender_and_kind(&event) else {
        return;
    };
    // Gate to-device verification events by trust boundary so a
    // hostile peer can't burn through the 256-record verification cap
    // and evict the operator's legitimate flow at index 0 (the cap-
    // eviction policy refuses active-flow eviction, but untrusted
    // peers still shouldn't be able to drive our verification state
    // machine). Two accepted classes:
    //
    //   1. `event.sender == config.user_id` — the operator's own
    //      device starting a self-verification flow with another of
    //      their devices. Most common operator path.
    //   2. `auto_join.allows_user(event.sender.as_str())` — a peer
    //      who is already trusted enough to auto-join a room with
    //      the bot is also trusted enough to start a verification
    //      flow.
    //
    // Anything else is dropped silently (warn-logged) — the peer
    // gets no SAS handshake; the operator can still initiate
    // verification toward an unlisted peer via
    // `cara matrix start-verification`, which goes through
    // `start_matrix_verification` and bypasses this handler.
    let sender_str = sender.as_str();
    let is_self = matrix_user_ids_equal(sender, &config.user_id);
    if !is_self && !config.auto_join.allows_user(sender_str) {
        let sender_san = sanitize_homeserver_identifier(sender_str);
        let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::AllowlistRejection);
        if should_log_matrix_peer_drop(drop_total) {
            warn!(
                sender = %sender_san,
                verification_event = event_kind,
                drop_total,
                drop_kind = MatrixPeerDropKind::AllowlistRejection.as_str(),
                "Matrix to-device verification event dropped: sender is not the configured user nor on the auto-join allowlist"
            );
        }
        return;
    }
    let AnyToDeviceEvent::KeyVerificationRequest(event) = event else {
        return;
    };
    let VerificationRecordUpsert::Applied {
        info: verification,
        inserted,
    } = upsert_verification_record(
        &state,
        event.content.transaction_id.to_string(),
        event.sender.to_string(),
        Some(event.content.from_device.to_string()),
        MatrixVerificationState::Requested,
    )
    else {
        let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::VerificationCapFull);
        if should_log_matrix_peer_drop(drop_total) {
            warn!(
                drop_total,
                drop_kind = MatrixPeerDropKind::VerificationCapFull.as_str(),
                "Matrix to-device KeyVerificationRequest dropped: verification record cap is full of active flows"
            );
        }
        return;
    };
    crate::server::ws::broadcast_matrix_verification_request(
        &ws_state,
        crate::server::ws::NewVerificationFlow::from_upsert(&verification, inserted),
    );
    // Suppress the `updated` event on fresh inserts — `requested`
    // already covers the state transition. See the inbound-message
    // handler for the same rationale (doubling broadcasts under
    // SAS-flood evicts operator dashboards via try_send-on-Full).
    if !inserted {
        crate::server::ws::broadcast_matrix_verification_updated(
            &ws_state,
            crate::server::ws::UpdatedVerificationFlow::for_state_change(&verification),
        );
    }
}

pub(super) fn matrix_to_device_verification_sender_and_kind(
    event: &AnyToDeviceEvent,
) -> Option<(&OwnedUserId, &'static str)> {
    match event {
        AnyToDeviceEvent::KeyVerificationRequest(event) => {
            Some((&event.sender, "m.key.verification.request"))
        }
        AnyToDeviceEvent::KeyVerificationReady(event) => {
            Some((&event.sender, "m.key.verification.ready"))
        }
        AnyToDeviceEvent::KeyVerificationStart(event) => {
            Some((&event.sender, "m.key.verification.start"))
        }
        AnyToDeviceEvent::KeyVerificationCancel(event) => {
            Some((&event.sender, "m.key.verification.cancel"))
        }
        AnyToDeviceEvent::KeyVerificationAccept(event) => {
            Some((&event.sender, "m.key.verification.accept"))
        }
        AnyToDeviceEvent::KeyVerificationKey(event) => {
            Some((&event.sender, "m.key.verification.key"))
        }
        AnyToDeviceEvent::KeyVerificationMac(event) => {
            Some((&event.sender, "m.key.verification.mac"))
        }
        AnyToDeviceEvent::KeyVerificationDone(event) => {
            Some((&event.sender, "m.key.verification.done"))
        }
        _ => None,
    }
}

/// Result of starting a Matrix verification flow.
///
/// Carries the upsert insertion flag so the caller can construct
/// `NewVerificationFlow::from_upsert(info, inserted)` and emit the
/// `matrix.verification.requested` event ONLY when the flow is fresh.
/// Without this, an operator-initiated `start-verification` for a peer
/// whose request already arrived inbound would re-broadcast
/// `requested` on top of the inbound-handler's broadcast, duplicating
/// UI notifications.
pub(crate) struct MatrixStartVerificationOutcome {
    pub info: MatrixVerificationInfo,
    pub inserted: bool,
}

#[derive(Debug, Clone)]
pub(super) enum VerificationRecordUpsert {
    Applied {
        info: MatrixVerificationInfo,
        inserted: bool,
    },
    RejectedAtCap,
}

impl VerificationRecordUpsert {
    #[cfg(test)]
    pub(super) fn unwrap_applied(self) -> (MatrixVerificationInfo, bool) {
        match self {
            Self::Applied { info, inserted } => (info, inserted),
            Self::RejectedAtCap => panic!("verification record upsert unexpectedly hit the cap"),
        }
    }
}

pub(super) async fn start_matrix_verification(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    user_id: String,
    device_id: Option<String>,
) -> Result<MatrixStartVerificationOutcome, MatrixError> {
    let parsed_user_id: OwnedUserId = user_id
        .parse::<OwnedUserId>()
        .map_err(|err| MatrixError::InvalidUserId(err.to_string()))?;
    let request = if let Some(device_id) = device_id.as_deref() {
        // The CLI's `cara matrix devices` listing renders the
        // sanitized form of `device_id` (terminal-display safety),
        // so an operator copy-pasting from the listing types the
        // sanitized string. The matrix-sdk's `get_device` indexes
        // by the RAW homeserver-original device_id. For
        // adversarial-or-misbehaving peer devices whose raw
        // device_id contains bidi / ZW / control bytes, the
        // operator's sanitized input misses the byte-exact lookup
        // and the verify command fails with DeviceNotFound — even
        // though the listing showed exactly that device.
        //
        // Resolve via sanitization-equivalence: try byte-exact
        // first (the steady-state case for all-ASCII device_ids);
        // if that misses, scan the user's full device list and
        // match by sanitized form. If multiple raw device_ids
        // sanitize to the same string, refuse — that's a
        // collision an adversary engineered, and silently picking
        // one device would let the adversary direct the
        // operator's verify into the wrong handle.
        let parsed_device_id: OwnedDeviceId = device_id.into();
        let device = match client
            .encryption()
            .get_device(&parsed_user_id, &parsed_device_id)
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
        {
            Some(device) => device,
            None => {
                // Byte-exact missed — try sanitization-equivalence.
                let user_devices = client
                    .encryption()
                    .get_user_devices(&parsed_user_id)
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                let mut matches: Vec<_> = user_devices
                    .devices()
                    .filter(|d| sanitize_homeserver_identifier(d.device_id().as_str()) == device_id)
                    .collect();
                if matches.len() > 1 {
                    return Err(MatrixError::Verification(format!(
                        "Matrix device id `{device_id}` matches multiple raw device_ids \
                         under sanitization-equivalence (sanitization collision — refusing \
                         to pick. Pass the raw bytes via the JSON device-list output's \
                         `rawDeviceIdHex` field if you need to disambiguate)"
                    )));
                }
                matches.pop().ok_or_else(|| MatrixError::DeviceNotFound {
                    user_id: user_id.clone(),
                    device_id: device_id.to_string(),
                })?
            }
        };
        device
            .request_verification()
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
    } else {
        let identity = client
            .encryption()
            .request_user_identity(&parsed_user_id)
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
            .ok_or_else(|| MatrixError::UserIdentityNotFound(user_id.clone()))?;
        identity
            .request_verification()
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
    };
    let state_label = verification_request_state_label(&request.state());
    let VerificationRecordUpsert::Applied { info, inserted } = upsert_verification_record(
        state,
        request.flow_id().to_string(),
        user_id,
        device_id,
        state_label,
    ) else {
        return Err(MatrixError::Verification(
            "Matrix verification record cap reached; no inactive verification records available to evict"
                .to_string(),
        ));
    };
    Ok(MatrixStartVerificationOutcome { info, inserted })
}

pub(super) fn matrix_verification_control_id(user_id: &str, protocol_flow_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"carapace-matrix-verification-control-id-v2\0");
    hasher.update(user_id.len().to_le_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(protocol_flow_id.len().to_le_bytes());
    hasher.update(protocol_flow_id.as_bytes());
    format!("mvr_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

pub(super) fn upsert_verification_record(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    protocol_flow_id: String,
    user_id: String,
    device_id: Option<String>,
    flow_state: MatrixVerificationState,
) -> VerificationRecordUpsert {
    // Sanitize for operator-visible surfaces (CLI SAS confirm
    // prompt, JSON wire, structured logs, WS broadcasts) but
    // preserve the raw bytes for SDK lookup. ruma's `OwnedDeviceId`
    // validator is a no-op so without sanitization an adversarial
    // peer can craft a device_id containing ANSI escapes that paint
    // a fake verification prompt. user_id and protocol_flow_id are
    // sanitized for defense-in-depth. The SDK internally indexes
    // by the raw flow id from the to-device event; passing the
    // sanitized form to `get_verification_request` would fail to
    // resolve any flow that contained stripped codepoints.
    let raw_protocol_flow_id = protocol_flow_id;
    let raw_user_id = user_id;
    let user_id = sanitize_homeserver_identifier(&raw_user_id);
    let device_id = device_id.map(|d| sanitize_homeserver_identifier(&d));
    let protocol_flow_id = sanitize_homeserver_identifier(&raw_protocol_flow_id);
    let now = now_millis();
    let flow_id = matrix_verification_control_id(&raw_user_id, &raw_protocol_flow_id);
    let mut guard = state.write();
    if let Some(flow) = guard
        .verifications
        .iter_mut()
        .find(|flow| flow.flow_id == flow_id)
    {
        flow.protocol_flow_id = protocol_flow_id;
        flow.raw_protocol_flow_id = raw_protocol_flow_id;
        flow.user_id = user_id;
        flow.device_id = device_id;
        flow.state = flow_state;
        // Preserve any previously captured SAS data on re-upsert. A
        // duplicate verification request from the peer (or a refresh
        // racing the upsert) would otherwise clear the emoji/decimals
        // the operator was about to compare. Fresh SAS data flows in
        // via `refresh_verification_records` which calls
        // `update_verification_record_state` with `Some(sas)` whenever
        // the SDK exposes new SAS values.
        flow.updated_at = now;
        let flow = flow.clone();
        return VerificationRecordUpsert::Applied {
            info: flow,
            inserted: false,
        };
    }
    // Enforce a hard cap before insert so a flood of fresh flow_ids
    // (allowlisted peer spam, redelivery storm) cannot grow the Vec
    // unbounded between TTL prunes. Eviction priority: terminal records
    // first, then unadvanced Requested records from the same peer. Never
    // evict another peer's pending or active SAS flow just to admit a new
    // request from a flooding peer.
    if guard.verifications.len() >= MATRIX_VERIFICATION_RECORDS_MAX {
        let Some(drop_index) = guard
            .verifications
            .iter()
            .position(|f| f.state.is_terminal())
            .or_else(|| {
                guard.verifications.iter().position(|f| {
                    f.state == MatrixVerificationState::Requested && f.user_id == user_id
                })
            })
        else {
            // Throttle: sustained SAS flood from an allowlisted-then-
            // hostile peer would otherwise emit one warn line per
            // incoming verification event. Cap to one per hour per
            // process — the operator's actionable signal is "peer
            // is flooding verification records", not the per-event
            // detail (which is bounded anyway by the rejection
            // return value).
            if matrix_verification_cap_warn_should_fire() {
                warn!(
                    cap = MATRIX_VERIFICATION_RECORDS_MAX,
                    user_id = %user_id,
                    "Matrix verification records hit cap without same-peer requested or terminal records; \
                     refusing to admit a new flow rather than evict another peer's verification"
                );
            }
            return VerificationRecordUpsert::RejectedAtCap;
        };
        let dropped = guard.verifications.remove(drop_index);
        if matrix_verification_cap_warn_should_fire() {
            warn!(
                cap = MATRIX_VERIFICATION_RECORDS_MAX,
                dropped_flow_id = %dropped.flow_id,
                dropped_state = %dropped.state,
                dropped_was_terminal = dropped.state.is_terminal(),
                "Matrix verification records hit cap; evicting oldest record \
                 (terminal-first) — may indicate a peer flooding fresh flow ids"
            );
        }
    }
    let flow = MatrixVerificationInfo {
        flow_id,
        protocol_flow_id,
        raw_protocol_flow_id,
        user_id,
        device_id,
        state: flow_state,
        sas: None,
        created_at: now,
        updated_at: now,
    };
    guard.verifications.push(flow.clone());
    VerificationRecordUpsert::Applied {
        info: flow,
        inserted: true,
    }
}

pub(super) async fn apply_verification_action(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    flow_id: &str,
    action: MatrixVerificationAction,
) -> Result<MatrixVerificationInfo, MatrixError> {
    let flow = state
        .read()
        .verifications
        .iter()
        .find(|flow| flow.flow_id == flow_id)
        .cloned()
        .ok_or_else(|| MatrixError::VerificationFlowNotFound(flow_id.to_string()))?;
    // Reject Accept/Confirm against an already-terminal flow with a
    // typed `VerificationCancelled` rather than `VerificationFlowNotReady`.
    // Cancelled/Done/Mismatched are permanent — retrying issues the
    // same SDK request and earns the same SDK rejection. Distinct
    // status code (HTTP 410 vs 409) helps the CLI/operator distinguish
    // "peer cancelled while you were typing" (security-relevant —
    // investigate why) from "you're racing the SDK" (transient —
    // retry). Exhaustive match (not `matches!`) so a future
    // MatrixVerificationAction variant compile-fails here, forcing
    // the contributor to deliberately classify whether the new
    // action needs the terminal-state guard.
    guard_verification_action_terminal_state(flow_id, &action, &flow.state)?;
    let audit_successful_confirm =
        matches!(action, MatrixVerificationAction::Confirm { matches: true });
    let parsed_user_id: OwnedUserId = flow
        .user_id
        .parse::<OwnedUserId>()
        .map_err(|err| MatrixError::InvalidUserId(err.to_string()))?;
    // SDK lookups must use the RAW flow id from the original
    // to-device event. The sanitized form on `protocol_flow_id` is
    // operator-display-only — passing it to
    // `client.encryption().get_verification_*` would fail to resolve
    // any flow whose original id contained codepoints stripped by
    // sanitize.
    let protocol_flow_id = flow.raw_protocol_flow_id.clone();

    let next_state = match action {
        MatrixVerificationAction::Accept => {
            let mut accepted = false;
            let mut next_state = None;
            let mut next_sas = None;
            if let Some(request) = client
                .encryption()
                .get_verification_request(&parsed_user_id, &protocol_flow_id)
                .await
            {
                request
                    .accept()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                accepted = true;
                if request.is_ready() {
                    if let Some(sas) = request
                        .start_sas()
                        .await
                        .map_err(|err| MatrixError::Verification(err.to_string()))?
                    {
                        next_sas = matrix_sas_info(&sas);
                        next_state = Some(sas_state_label(&sas.state()));
                    }
                }
                if next_state.is_none() {
                    next_state = Some(verification_request_state_label(&request.state()));
                }
            }
            if !accepted {
                if let Some(sas) = client
                    .encryption()
                    .get_verification(&parsed_user_id, &protocol_flow_id)
                    .await
                    .and_then(|verification| verification.sas())
                {
                    sas.accept()
                        .await
                        .map_err(|err| MatrixError::Verification(err.to_string()))?;
                    accepted = true;
                    next_sas = matrix_sas_info(&sas);
                    next_state = Some(sas_state_label(&sas.state()));
                }
            }
            if !accepted {
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "accept",
                });
            }
            let final_state = next_state.unwrap_or(MatrixVerificationState::Accepted);
            (final_state, next_sas)
        }
        MatrixVerificationAction::Confirm { matches } => {
            // Refuse to call sas.confirm() unless the daemon has
            // previously captured SAS data for this flow. The stored
            // `flow.sas` is populated by `refresh_verification_records`
            // (called on every successful sync) and surfaced via the
            // verifications GET endpoint so the operator can compare
            // emoji/decimals before confirming. Without this guard, an
            // operator who knows a flow_id can confirm a verification
            // they have never seen the SAS for, defeating the entire
            // point of SAS verification (a MITM-resistant manual
            // comparison).
            if flow.sas.is_none() {
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "confirm",
                });
            }
            let Some(sas) = client
                .encryption()
                .get_verification(&parsed_user_id, &protocol_flow_id)
                .await
                .and_then(|verification| verification.sas())
            else {
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "confirm",
                });
            };
            if matches {
                sas.confirm()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                (sas_state_label(&sas.state()), matrix_sas_info(&sas))
            } else {
                sas.mismatch()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                (MatrixVerificationState::Mismatched, matrix_sas_info(&sas))
            }
        }
        MatrixVerificationAction::Cancel => {
            let mut cancelled = false;
            let mut sas_info: Option<MatrixSasInfo> = None;
            if let Some(request) = client
                .encryption()
                .get_verification_request(&parsed_user_id, &protocol_flow_id)
                .await
            {
                request
                    .cancel()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                cancelled = true;
            }
            if let Some(sas) = client
                .encryption()
                .get_verification(&parsed_user_id, &protocol_flow_id)
                .await
                .and_then(|verification| verification.sas())
            {
                sas_info = matrix_sas_info(&sas);
                sas.cancel()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                cancelled = true;
            }
            if !cancelled {
                // Cancel is idempotent: if the SDK no longer has either
                // a request or SAS view but our local record is already
                // terminal (e.g. previously cancelled, or the SDK
                // garbage-collected after a peer-side cancel), treat
                // this as a no-op success rather than 409 ConflictNotReady.
                if flow.state.is_terminal() {
                    return Ok(flow);
                }
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "cancel",
                });
            }
            (MatrixVerificationState::Cancelled, sas_info)
        }
    };

    update_verification_record_state(
        state,
        flow_id,
        next_state.0,
        SasUpdate::from_optional(next_state.1),
    )?;
    let info = state
        .read()
        .verifications
        .iter()
        .find(|f| f.flow_id == flow_id)
        .cloned()
        .ok_or_else(|| MatrixError::VerificationFlowNotFound(flow_id.to_string()))?;
    if audit_successful_confirm {
        warn!(
            audit_event = "matrix_device_verification_confirmed",
            flow_id = %info.flow_id,
            protocol_flow_id = %info.protocol_flow_id,
            user_id = %info.user_id,
            device_id = %info.device_id.as_deref().unwrap_or("<user-identity>"),
            state = %info.state.as_wire_str(),
            "Matrix SAS-confirmed verification trust grant completed"
        );
    }
    prune_finished_verification_records(state);
    Ok(info)
}

pub(super) fn guard_verification_action_terminal_state(
    flow_id: &str,
    action: &MatrixVerificationAction,
    flow_state: &MatrixVerificationState,
) -> Result<(), MatrixError> {
    let needs_terminal_guard = match action {
        MatrixVerificationAction::Accept | MatrixVerificationAction::Confirm { .. } => true,
        // Cancel is idempotent on terminal flows.
        MatrixVerificationAction::Cancel => false,
    };
    if needs_terminal_guard && flow_state.is_terminal() {
        return Err(MatrixError::VerificationCancelled {
            flow_id: flow_id.to_string(),
            state: flow_state.clone(),
        });
    }
    Ok(())
}

/// How a verification-state update should treat the stored SAS data.
///
/// Earlier the helper accepted `Option<MatrixSasInfo>` where `None`
/// meant "preserve" — the signature read as "no SAS available," which
/// was the opposite of the actual behavior (preserve). Encoding the
/// choice in a sum type makes call sites self-documenting and prevents
/// a contributor from accidentally clobbering SAS by passing `None`
/// when they meant "I have no fresh SAS to install."
#[derive(Debug, Clone)]
pub(super) enum SasUpdate {
    /// Keep `flow.sas` as-is. Used by the refresh path when the SDK
    /// surfaces only a `VerificationRequest` view (no active SAS) so
    /// the operator's previously captured emoji/decimals don't vanish
    /// across state transitions.
    Preserve,
    /// Replace `flow.sas` with the fresh SAS data captured from the
    /// SDK after a SAS-state-producing transition.
    Set(MatrixSasInfo),
}

impl SasUpdate {
    fn from_optional(sas: Option<MatrixSasInfo>) -> Self {
        match sas {
            Some(sas) => SasUpdate::Set(sas),
            None => SasUpdate::Preserve,
        }
    }
}

pub(super) fn update_verification_record_state(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    flow_id: &str,
    next_state: MatrixVerificationState,
    sas: SasUpdate,
) -> Result<Option<MatrixVerificationInfo>, MatrixError> {
    let mut guard = state.write();
    let Some(flow) = guard
        .verifications
        .iter_mut()
        .find(|flow| flow.flow_id == flow_id)
    else {
        return Err(MatrixError::VerificationFlowNotFound(flow_id.to_string()));
    };
    let next_sas = match sas {
        SasUpdate::Set(sas) => Some(sas),
        SasUpdate::Preserve => flow.sas.clone(),
    };
    if flow.state == next_state && flow.sas == next_sas {
        return Ok(None);
    }
    flow.updated_at = now_millis();
    flow.sas = next_sas;
    flow.state = next_state;
    Ok(Some(flow.clone()))
}

pub(super) async fn refresh_verification_records(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    ws_state: &Arc<WsServerState>,
) -> Result<(), MatrixError> {
    // Parallelism follow-up: the per-record SDK lookups
    // (`get_verification_request`, `get_verification`) below run
    // sequentially. With the cap at MATRIX_VERIFICATION_RECORDS_MAX
    // (256) and per-call cost dominated by the encrypted-SQLite store
    // read inside OlmMachine, a fully populated table can spend a
    // measurable fraction of MATRIX_RUNTIME_OPERATION_TIMEOUT (30s)
    // in this loop under contention. State mutations per record are
    // independent (each `update_verification_record_state` takes a
    // separate write-lock), so a bounded-parallelism rewrite using
    // `futures::stream::buffer_unordered(8..16)` or a `JoinSet` would
    // collapse 256× into ~256/k × per-call without ordering hazards.
    // Tracked as a separate PR because the change is orthogonal to
    // the current Matrix-channel security/correctness work.
    prune_verification_records(state);
    let records = state.read().verifications.clone();
    // Per-tick cap for the malformed-user_id warn. Stored records
    // come from peer-controlled events that we accepted, so a hostile
    // peer who slipped a malformed user_id past validation would
    // otherwise emit one warn per record per maintenance tick until
    // the TTL prunes them. The records are bounded at
    // MATRIX_VERIFICATION_RECORDS_MAX (256), so the worst-case flood
    // is 256 warns/tick — still worth capping for cleaner operator
    // logs under sustained replay.
    const INVALID_USER_ID_WARN_CAP: usize = 10;
    let mut invalid_user_id_warn_count = 0usize;
    let mut suppressed_invalid_user_id_warn_count = 0usize;
    for record in records {
        let parsed_user_id: OwnedUserId = match record.user_id.parse() {
            Ok(user_id) => user_id,
            Err(err) => {
                // Skip the record rather than aborting the loop. With
                // inline broadcasts, an early `return Err` would emit
                // the broadcasts that already landed but skip every
                // remaining record — mid-loop partial progress with
                // no recovery on the next tick. A malformed stored
                // user_id is operator-visible at warn level and the
                // record will be pruned by TTL eventually.
                if invalid_user_id_warn_count < INVALID_USER_ID_WARN_CAP {
                    invalid_user_id_warn_count += 1;
                    warn!(
                        flow_id = %record.flow_id,
                        error = %err,
                        "invalid Matrix verification user ID; skipping record this tick",
                    );
                } else {
                    suppressed_invalid_user_id_warn_count += 1;
                }
                continue;
            }
        };
        // Always probe both the request view AND the SAS view. The
        // earlier short-circuit (`if Some(request) -> use request, else if
        // Some(sas) -> use sas`) meant a flow that advanced from
        // request-state into SAS-state without garbage-collecting the
        // request would never refresh its SAS into our local record —
        // and combined with the confirm-requires-flow.sas guard, that
        // could leave a valid SAS-state flow stuck unable to confirm.
        let request = client
            .encryption()
            .get_verification_request(&parsed_user_id, &record.raw_protocol_flow_id)
            .await;
        let sas = client
            .encryption()
            .get_verification(&parsed_user_id, &record.raw_protocol_flow_id)
            .await
            .and_then(|verification| verification.sas());
        let (next_state, next_sas) = match (request, sas) {
            (_, Some(sas)) => (sas_state_label(&sas.state()), matrix_sas_info(&sas)),
            (Some(request), None) => (verification_request_state_label(&request.state()), None),
            (None, None) => {
                debug!(
                    flow_id = %record.flow_id,
                    "Matrix verification record has no SDK view; awaiting prune"
                );
                continue;
            }
        };
        match update_verification_record_state(
            state,
            &record.flow_id,
            next_state,
            SasUpdate::from_optional(next_sas),
        ) {
            Ok(Some(updated)) => {
                // Broadcast immediately after each successful state
                // mutation. The previous shape collected updates into a
                // Vec and broadcast at the end, but the call site wraps
                // this future in a 30-second timeout — a mid-iteration
                // cancel dropped the Vec while the state mutations had
                // already landed, and the next refresh's `Ok(None)`
                // dedupe meant the broadcast was permanently lost.
                // Broadcasting inline guarantees every mutation that
                // commits to state is also delivered to clients.
                crate::server::ws::broadcast_matrix_verification_updated(
                    ws_state,
                    crate::server::ws::UpdatedVerificationFlow::for_state_change(&updated),
                );
            }
            Ok(None) => {}
            Err(err) => {
                debug!(
                    flow_id = %record.flow_id,
                    error = %err,
                    "Matrix verification update skipped (record disappeared mid-refresh)"
                );
                continue;
            }
        }
    }
    if suppressed_invalid_user_id_warn_count > 0 {
        warn!(
            suppressed = suppressed_invalid_user_id_warn_count,
            logged = invalid_user_id_warn_count,
            "Matrix verification records with invalid user_id (suppressed remainder; \
             records will be pruned by TTL — investigate the upstream that admitted them)"
        );
    }
    prune_finished_verification_records(state);
    Ok(())
}

pub(super) fn verification_request_state_label(
    state: &VerificationRequestState,
) -> MatrixVerificationState {
    match state {
        VerificationRequestState::Created { .. } => MatrixVerificationState::Created,
        VerificationRequestState::Requested { .. } => MatrixVerificationState::Requested,
        VerificationRequestState::Ready { .. } => MatrixVerificationState::Ready,
        VerificationRequestState::Transitioned { .. } => MatrixVerificationState::Transitioned,
        VerificationRequestState::Done => MatrixVerificationState::Done,
        VerificationRequestState::Cancelled(_) => MatrixVerificationState::Cancelled,
    }
}

pub(super) fn sas_state_label(state: &SasState) -> MatrixVerificationState {
    match state {
        SasState::Created { .. } => MatrixVerificationState::Created,
        SasState::Started { .. } => MatrixVerificationState::Started,
        SasState::Accepted { .. } => MatrixVerificationState::Accepted,
        SasState::KeysExchanged { .. } => MatrixVerificationState::KeysExchanged,
        SasState::Confirmed => MatrixVerificationState::Confirmed,
        SasState::Done { .. } => MatrixVerificationState::Done,
        SasState::Cancelled(_) => MatrixVerificationState::Cancelled,
    }
}

pub(super) fn matrix_sas_info(sas: &SasVerification) -> Option<MatrixSasInfo> {
    let emoji = sas.emoji().map(|emojis| {
        emojis
            .iter()
            .map(|emoji| MatrixSasEmoji {
                symbol: emoji.symbol.to_string(),
                description: emoji.description.to_string(),
            })
            .collect::<Vec<_>>()
    });
    let decimals = sas
        .decimals()
        .map(|(first, second, third)| [first, second, third]);
    if emoji.is_none() && decimals.is_none() {
        None
    } else {
        Some(MatrixSasInfo { emoji, decimals })
    }
}

pub(super) fn prune_verification_records(state: &Arc<RwLock<MatrixRuntimeState>>) {
    let now = match try_now_millis() {
        Ok(now) => now,
        Err(err) => {
            warn!(error = %err, "skipping Matrix verification prune because wall clock is invalid");
            return;
        }
    };
    let cutoff = now.saturating_sub(MATRIX_VERIFICATION_RECORD_TTL.as_millis() as i64);
    let mut guard = state.write();
    guard.verifications.retain(|flow| flow.updated_at >= cutoff);
}

pub(super) fn prune_finished_verification_records(state: &Arc<RwLock<MatrixRuntimeState>>) {
    let mut guard = state.write();
    guard.verifications.retain(|flow| !flow.state.is_terminal());
}

/// One-per-hour throttle gate for the verification-cap warns
/// (`upsert_verification_record` reject-at-cap and evict-on-cap). A
/// sustained SAS flood from an allowlisted-then-hostile peer would
/// otherwise emit one warn line per incoming verification event,
/// defeating the caller-side `should_log_matrix_peer_drop` throttle
/// and amplifying log volume. The actionable operator signal is
/// "peer is flooding", not the per-event detail. Same AtomicU64 CAS
/// pattern used by the audit-channel-drop and plugins-manifest
/// near-cap throttles.
pub(super) fn matrix_verification_cap_warn_should_fire() -> bool {
    static LAST_WARN_AT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    crate::logging::throttle::throttled_once_per_hour(&LAST_WARN_AT_SECS)
}
