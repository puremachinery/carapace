//! Matrix SAS verification state.
//!
//! This module owns daemon-side verification records, Matrix protocol flow
//! lookup, and the control actions that advance SAS handshakes. Records keep
//! sanitized protocol/device identifiers for operator-visible JSON/log
//! surfaces while keeping typed user identifiers and raw protocol flow ids
//! for SDK lookups.

use super::*;
use matrix_sdk::encryption::verification::{SasState, SasVerification, VerificationRequestState};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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
    /// Matrix user id for operator-visible surfaces.
    pub user_id: OwnedUserId,
    /// Raw Matrix user id as supplied by the SDK. Skipped from wire
    /// serialization; runtime constructors set it from the same typed
    /// boundary as `user_id`.
    #[serde(skip)]
    pub raw_user_id: OwnedUserId,
    /// Device id of the peer being verified, or absent when the
    /// protocol flow targets the user without a specific device.
    /// `skip_serializing_if = Option::is_none` matches the convention
    /// on `sas` below: omit-when-absent rather than emit `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<OwnedDeviceId>,
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

impl<'de> Deserialize<'de> for MatrixVerificationInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            flow_id: String,
            protocol_flow_id: String,
            user_id: OwnedUserId,
            device_id: Option<OwnedDeviceId>,
            state: MatrixVerificationState,
            #[serde(default)]
            sas: Option<MatrixSasInfo>,
            created_at: i64,
            updated_at: i64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            flow_id: wire.flow_id,
            raw_protocol_flow_id: wire.protocol_flow_id.clone(),
            protocol_flow_id: wire.protocol_flow_id,
            raw_user_id: wire.user_id.clone(),
            user_id: wire.user_id,
            device_id: wire.device_id,
            state: wire.state,
            sas: wire.sas,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        })
    }
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
        event.sender.clone(),
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
pub(super) struct MatrixStartVerificationOutcome {
    pub info: MatrixVerificationInfo,
    pub inserted: bool,
}

#[derive(Debug, Clone)]
pub(super) enum VerificationRecordUpsert {
    Applied {
        info: Box<MatrixVerificationInfo>,
        inserted: bool,
    },
    RejectedAtCap,
}

impl VerificationRecordUpsert {
    #[cfg(test)]
    pub(super) fn unwrap_applied(self) -> (MatrixVerificationInfo, bool) {
        match self {
            Self::Applied { info, inserted } => (*info, inserted),
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
        parsed_user_id.clone(),
        device_id,
        state_label,
    ) else {
        return Err(MatrixError::Verification(
            "Matrix verification record cap reached; no inactive verification records available to evict"
                .to_string(),
        ));
    };
    Ok(MatrixStartVerificationOutcome {
        info: *info,
        inserted,
    })
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
    user_id: OwnedUserId,
    device_id: Option<String>,
    flow_state: MatrixVerificationState,
) -> VerificationRecordUpsert {
    // Sanitize peer-controlled protocol/device ids for operator-visible
    // surfaces (CLI SAS confirm prompt, JSON wire, structured logs, WS
    // broadcasts) but preserve the raw protocol flow id for SDK lookup.
    // ruma's `OwnedDeviceId` validator is a no-op, so without sanitization
    // an adversarial peer can craft a device_id containing ANSI escapes
    // that paint a fake verification prompt. The SDK internally indexes
    // by the raw flow id from the to-device event; passing the sanitized
    // form to `get_verification_request` would fail to resolve any flow
    // that contained stripped codepoints.
    let raw_protocol_flow_id = protocol_flow_id;
    let raw_user_id = user_id;
    let user_id = raw_user_id.clone();
    let device_id = device_id.map(|d| OwnedDeviceId::from(sanitize_homeserver_identifier(&d)));
    let protocol_flow_id = sanitize_homeserver_identifier(&raw_protocol_flow_id);
    let now = now_millis();
    let flow_id = matrix_verification_control_id(raw_user_id.as_str(), &raw_protocol_flow_id);
    let mut guard = state.write();
    if let Some(flow) = guard
        .verifications
        .iter_mut()
        .find(|flow| flow.flow_id == flow_id)
    {
        flow.protocol_flow_id = protocol_flow_id;
        flow.raw_protocol_flow_id = raw_protocol_flow_id;
        flow.user_id = user_id;
        flow.raw_user_id = raw_user_id;
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
            info: Box::new(flow),
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
                    f.state == MatrixVerificationState::Requested && f.raw_user_id == raw_user_id
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
        raw_user_id,
        device_id,
        state: flow_state,
        sas: None,
        created_at: now,
        updated_at: now,
    };
    guard.verifications.push(flow.clone());
    VerificationRecordUpsert::Applied {
        info: Box::new(flow),
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
    let parsed_user_id = flow.raw_user_id.clone();
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
            device_id = %info.device_id.as_ref().map(|id| id.as_str()).unwrap_or("<user-identity>"),
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
    for record in records {
        let parsed_user_id = record.raw_user_id.clone();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::matrix::matrix_rs_fn_body;
    use serde_json::json;

    fn test_owned_user_id(value: &str) -> OwnedUserId {
        value.parse().expect("user id")
    }

    /// `update_verification_record_state` must preserve previously
    /// captured SAS data when the caller passes `SasUpdate::Preserve`
    /// — regression test pinning that emoji stay visible across state
    /// transitions instead of being clobbered on every refresh
    /// iteration.
    #[test]
    fn test_update_verification_record_state_preserves_sas_when_next_is_none() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, inserted) = upsert_verification_record(
            &state,
            "abc123".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        let flow_id = info.flow_id.clone();
        let seeded_sas = MatrixSasInfo {
            emoji: Some(vec![MatrixSasEmoji {
                symbol: "🐱".to_string(),
                description: "Cat".to_string(),
            }]),
            decimals: Some([1, 2, 3]),
        };
        update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::KeysExchanged,
            SasUpdate::Set(seeded_sas.clone()),
        )
        .expect("seed SAS");

        // Preserve must keep the SAS intact even though the state advances.
        update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::Confirmed,
            SasUpdate::Preserve,
        )
        .expect("preserve");
        let stored = state
            .read()
            .verifications
            .iter()
            .find(|f| f.flow_id == flow_id)
            .cloned()
            .expect("flow exists");
        assert_eq!(stored.state, MatrixVerificationState::Confirmed);
        assert_eq!(stored.sas, Some(seeded_sas.clone()));

        // Set replaces.
        let replacement = MatrixSasInfo {
            emoji: None,
            decimals: Some([9, 8, 7]),
        };
        update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::Done,
            SasUpdate::Set(replacement.clone()),
        )
        .expect("set");
        let stored = state
            .read()
            .verifications
            .iter()
            .find(|f| f.flow_id == flow_id)
            .cloned()
            .expect("flow exists");
        assert_eq!(stored.sas, Some(replacement));
    }

    /// `update_verification_record_state` returns `Ok(None)` when the
    /// requested next state and SAS are equal to the existing record
    /// (no-op tick) — refresh broadcasts only fire on real change;
    /// this test pins that contract.
    #[test]
    fn test_update_verification_record_state_returns_none_on_noop() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, inserted) = upsert_verification_record(
            &state,
            "noop-flow".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        let flow_id = info.flow_id.clone();
        // Same state, SasUpdate::Preserve (so SAS stays None) — must
        // return Ok(None) so the broadcast caller knows nothing changed.
        let result = update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::Requested,
            SasUpdate::Preserve,
        )
        .expect("call");
        assert!(
            result.is_none(),
            "no-op state update must return None so refresh broadcasts only fire on real change"
        );
    }

    /// A real state change must return `Ok(Some(record))` so the
    /// caller can broadcast `matrix.verification.updated` with the
    /// post-state record.
    #[test]
    fn test_update_verification_record_state_returns_some_on_change() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, _) = upsert_verification_record(
            &state,
            "change-flow".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        let flow_id = info.flow_id.clone();
        let result = update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::KeysExchanged,
            SasUpdate::Preserve,
        )
        .expect("call");
        let updated = result.expect("real change must return Some");
        assert_eq!(updated.state, MatrixVerificationState::KeysExchanged);
    }

    /// A SAS-only change with the same state must still report the
    /// change. Otherwise a refresh that captures fresh SAS data on a
    /// flow that's been in `KeysExchanged` for a while would fail to
    /// broadcast and the operator UI would never see the comparison
    /// emoji.
    #[test]
    fn test_update_verification_record_state_returns_some_when_sas_changes() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, _) = upsert_verification_record(
            &state,
            "sas-flow".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE".to_string()),
            MatrixVerificationState::KeysExchanged,
        )
        .unwrap_applied();
        let flow_id = info.flow_id.clone();
        let new_sas = MatrixSasInfo {
            emoji: None,
            decimals: Some([1, 2, 3]),
        };
        let result = update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::KeysExchanged,
            SasUpdate::Set(new_sas.clone()),
        )
        .expect("call");
        let updated = result.expect("SAS change must return Some");
        assert_eq!(updated.sas, Some(new_sas));
    }

    /// Pin the JSON shape of `MatrixVerificationInfo` against the
    /// schema declared in `tests/golden/ws/events.json`. If the
    /// runtime adds/removes a public field on the verification info,
    /// the golden schema must be updated in lockstep — this test
    /// catches drift before WS clients see it.
    #[test]
    fn test_matrix_verification_info_serializes_required_fields() {
        let info = MatrixVerificationInfo {
            flow_id: "flow-1".to_string(),
            protocol_flow_id: "txn-1".to_string(),
            raw_protocol_flow_id: "txn-1".to_string(),
            user_id: "@alice:example.com".parse().expect("user id"),
            raw_user_id: "@alice:example.com".parse().expect("user id"),
            device_id: Some("DEVICE".into()),
            state: MatrixVerificationState::Requested,
            sas: None,
            created_at: 1,
            updated_at: 2,
        };
        let json = serde_json::to_value(&info).expect("serialize");
        // Required fields per the WS event schema.
        for field in [
            "flowId",
            "protocolFlowId",
            "userId",
            "state",
            "createdAt",
            "updatedAt",
        ] {
            assert!(
                json.get(field).is_some(),
                "MatrixVerificationInfo must serialize {field}"
            );
        }
        // State must serialize to one of the documented values.
        let state_str = json
            .get("state")
            .and_then(|v| v.as_str())
            .expect("state is string");
        let allowed = [
            "created",
            "requested",
            "ready",
            "transitioned",
            "started",
            "accepted",
            "keys_exchanged",
            "confirmed",
            "done",
            "cancelled",
            "mismatched",
        ];
        assert!(
            allowed.contains(&state_str),
            "MatrixVerificationState '{state_str}' is not in the documented enum"
        );
    }

    /// Pin: `upsert_verification_record` stores BOTH the sanitized
    /// protocol-flow identifier (operator-display surface) and the raw
    /// protocol-flow identifier (SDK lookup key / internal equality).
    /// Sanitization is non-bijective; passing the sanitized form to
    /// `client.encryption().get_verification_*` would fail to
    /// resolve any flow whose original id contained codepoints
    /// stripped by sanitize. `apply_verification_action` MUST use
    /// the raw form for SDK lookups.
    #[test]
    fn test_upsert_verification_record_preserves_raw_protocol_fields() {
        let runtime_state = Arc::new(parking_lot::RwLock::new(MatrixRuntimeState::default()));
        // Inject a hostile-shape protocol flow id with a zero-width
        // joiner. Sanitize strips ZWJs (U+200D); the raw must be
        // preserved exactly so SDK lookup matches.
        let raw_flow = "txn-\u{200d}-abc";
        let sanitized_flow = "txn--abc";
        let raw_user_id = test_owned_user_id("@alice:example.com");
        let (info, _inserted) = upsert_verification_record(
            &runtime_state,
            raw_flow.to_string(),
            raw_user_id.clone(),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert_eq!(
            info.raw_protocol_flow_id, raw_flow,
            "raw_protocol_flow_id must preserve the original bytes for SDK lookup"
        );
        assert_eq!(
            info.protocol_flow_id, sanitized_flow,
            "protocol_flow_id must be sanitized for operator-display surfaces"
        );
        assert_eq!(
            info.raw_user_id, raw_user_id,
            "raw_user_id must carry the typed SDK lookup key"
        );
        assert_eq!(
            info.user_id, raw_user_id,
            "user_id and raw_user_id are the same validated Matrix user id"
        );
        // Wire serialization MUST omit raw_* fields (they
        // would defeat the whole point: operator scripts decoding the
        // wire JSON would see un-sanitized bytes).
        let json = serde_json::to_value(&info).expect("serialize");
        assert!(
            json.get("rawProtocolFlowId").is_none() && json.get("raw_protocol_flow_id").is_none(),
            "raw_protocol_flow_id must NOT serialize to wire JSON"
        );
        assert!(
            json.get("rawUserId").is_none() && json.get("raw_user_id").is_none(),
            "raw_user_id must NOT serialize to wire JSON"
        );
        let decoded: MatrixVerificationInfo =
            serde_json::from_value(json).expect("deserialize verification info");
        assert_eq!(
            decoded.raw_protocol_flow_id, decoded.protocol_flow_id,
            "wire deserialization must reconstruct raw_protocol_flow_id from the public protocolFlowId"
        );
        assert_eq!(
            decoded.raw_user_id, decoded.user_id,
            "wire deserialization must reconstruct raw_user_id from the public typed userId"
        );
    }

    /// Pin: `apply_verification_action` resolves SDK lookups via the
    /// `raw_protocol_flow_id` field, never the sanitized form.
    /// Static-analysis pin against the function body: the let-binding
    /// must be `flow.raw_protocol_flow_id.clone()` and `protocol_flow_id`
    /// must NOT be re-bound to `flow.protocol_flow_id` (the sanitized
    /// form) anywhere in the SDK-call section.
    #[test]
    fn test_apply_verification_action_uses_raw_for_sdk_lookup() {
        let body = matrix_rs_fn_body("async fn apply_verification_action");
        let body = body.as_str();
        assert!(
            body.contains("let protocol_flow_id = flow.raw_protocol_flow_id.clone();"),
            "apply_verification_action must clone raw_protocol_flow_id for SDK lookup"
        );
        assert!(
            body.contains("let parsed_user_id = flow.raw_user_id.clone();"),
            "apply_verification_action must use typed raw_user_id for SDK lookup"
        );
        assert!(
            !body.contains("let protocol_flow_id = flow.protocol_flow_id.clone();"),
            "apply_verification_action must NOT re-bind protocol_flow_id to the \
             sanitized field; sanitize is non-bijective and SDK lookup would fail"
        );
        assert!(
            !body.contains(".user_id\n        .parse::<OwnedUserId>()"),
            "apply_verification_action must not parse the public user_id for SDK lookup"
        );
    }

    /// Pin: `refresh_verification_records` also resolves SDK
    /// lookups via the raw protocol flow id. A ZWSP / bidi /
    /// control-stripped flow can sit in the daemon list long enough
    /// for the refresh worker to update it; using the sanitized
    /// display field there would make refresh mark the flow stale
    /// while `apply_verification_action` still finds it.
    #[test]
    fn test_refresh_verification_records_uses_raw_for_sdk_lookup() {
        let body = matrix_rs_fn_body("async fn refresh_verification_records");
        let body = body.as_str();
        assert!(
            body.contains(
                "get_verification_request(&parsed_user_id, &record.raw_protocol_flow_id)"
            ),
            "refresh_verification_records must use raw_protocol_flow_id for request lookup"
        );
        assert!(
            body.contains("get_verification(&parsed_user_id, &record.raw_protocol_flow_id)"),
            "refresh_verification_records must use raw_protocol_flow_id for SAS lookup"
        );
        assert!(
            body.contains("let parsed_user_id = record.raw_user_id.clone();"),
            "refresh_verification_records must use typed raw_user_id for SDK lookup"
        );
        assert!(
            !body.contains("get_verification_request(&parsed_user_id, &record.protocol_flow_id)")
                && !body.contains("get_verification(&parsed_user_id, &record.protocol_flow_id)"),
            "refresh_verification_records must not use the sanitized protocol_flow_id for SDK lookups"
        );
        assert!(
            !body.contains("record.user_id.parse()"),
            "refresh_verification_records must not parse the public user_id for SDK lookup"
        );
    }

    #[test]
    fn test_verification_record_upsert_and_prune() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (first, inserted) = upsert_verification_record(
            &state,
            "protocol-flow-1".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE1".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        assert_eq!(first.protocol_flow_id, "protocol-flow-1");
        assert_eq!(first.state, MatrixVerificationState::Requested);

        let (updated, inserted) = upsert_verification_record(
            &state,
            "protocol-flow-1".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE2".to_string()),
            MatrixVerificationState::Ready,
        )
        .unwrap_applied();
        assert!(!inserted);
        assert_eq!(
            updated.device_id.as_ref().map(|id| id.as_str()),
            Some("DEVICE2")
        );
        assert_eq!(updated.state, MatrixVerificationState::Ready);

        state.write().verifications[0].updated_at =
            now_millis() - MATRIX_VERIFICATION_RECORD_TTL.as_millis() as i64 - 1;
        prune_verification_records(&state);
        assert!(state.read().verifications.is_empty());
    }

    #[test]
    fn test_matrix_verification_info_wire_shape_is_camel_case_and_raw_safe() {
        let info = MatrixVerificationInfo {
            flow_id: "mvr_test".to_string(),
            protocol_flow_id: "txn-safe".to_string(),
            raw_protocol_flow_id: "txn-\u{200b}-raw".to_string(),
            user_id: "@alice:example.com".parse().expect("user id"),
            raw_user_id: "@alice:example.com".parse().expect("user id"),
            device_id: Some("DEVICE".into()),
            state: MatrixVerificationState::KeysExchanged,
            sas: Some(MatrixSasInfo {
                emoji: Some(vec![MatrixSasEmoji {
                    symbol: "🐱".to_string(),
                    description: "Cat".to_string(),
                }]),
                decimals: Some([1234, 5678, 9012]),
            }),
            created_at: 10,
            updated_at: 20,
        };

        let json = serde_json::to_value(&info).expect("serialize verification info");
        assert_eq!(json["flowId"], "mvr_test");
        assert_eq!(json["protocolFlowId"], "txn-safe");
        assert!(json.get("rawProtocolFlowId").is_none());
        assert!(json.get("raw_protocol_flow_id").is_none());
        assert_eq!(json["userId"], "@alice:example.com");
        assert!(json.get("rawUserId").is_none());
        assert!(json.get("raw_user_id").is_none());
        assert_eq!(json["deviceId"], "DEVICE");
        assert_eq!(json["state"], "keys_exchanged");
        assert_eq!(json["createdAt"], 10);
        assert_eq!(json["updatedAt"], 20);
        assert_eq!(
            json.pointer("/sas/decimals"),
            Some(&json!([1234, 5678, 9012]))
        );
        assert_eq!(json.pointer("/sas/emoji/0/symbol"), Some(&json!("🐱")));
        assert_eq!(
            json.pointer("/sas/emoji/0/description"),
            Some(&json!("Cat"))
        );
    }

    #[test]
    fn test_matrix_sas_info_wire_shape_omits_absent_optional_fields() {
        let sas = MatrixSasInfo {
            emoji: None,
            decimals: Some([1, 2, 3]),
        };
        let json = serde_json::to_value(&sas).expect("serialize sas info");
        assert_eq!(json, json!({ "decimals": [1, 2, 3] }));

        let emoji = MatrixSasEmoji {
            symbol: "7".to_string(),
            description: "Seven".to_string(),
        };
        let json = serde_json::to_value(&emoji).expect("serialize sas emoji");
        assert_eq!(json, json!({ "symbol": "7", "description": "Seven" }));
    }

    #[test]
    fn test_verification_control_id_includes_user_and_protocol_flow() {
        assert_eq!(
            matrix_verification_control_id("@alice:example.com", "shared-protocol-flow"),
            matrix_verification_control_id("@alice:example.com", "shared-protocol-flow"),
            "daemon control ids must be deterministic for the same raw peer flow"
        );
        assert!(
            matrix_verification_control_id("@alice:example.com", "shared-protocol-flow")
                .starts_with("mvr_"),
            "daemon control ids must live in the Matrix verification request namespace"
        );
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (alice, inserted) = upsert_verification_record(
            &state,
            "shared-protocol-flow".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE1".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        let (bob, inserted) = upsert_verification_record(
            &state,
            "shared-protocol-flow".to_string(),
            test_owned_user_id("@bob:example.com"),
            Some("DEVICE2".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        assert_ne!(alice.flow_id, bob.flow_id);
        assert_eq!(state.read().verifications.len(), 2);

        let sanitized_collision = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (raw_with_zwsp, inserted) = upsert_verification_record(
            &sanitized_collision,
            "flow-\u{200b}-id".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE1".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        let (raw_without_zwsp, inserted) = upsert_verification_record(
            &sanitized_collision,
            "flow--id".to_string(),
            test_owned_user_id("@alice:example.com"),
            Some("DEVICE1".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        assert_eq!(
            raw_with_zwsp.protocol_flow_id,
            raw_without_zwsp.protocol_flow_id
        );
        assert_ne!(
            raw_with_zwsp.flow_id, raw_without_zwsp.flow_id,
            "peer protocol ids that sanitize to the same display id must not collide in daemon control ids"
        );
        assert_eq!(sanitized_collision.read().verifications.len(), 2);
    }

    #[test]
    fn test_verification_state_serde_round_trip_and_terminal() {
        let encoded = serde_json::to_value(MatrixVerificationState::KeysExchanged).unwrap();
        assert_eq!(encoded, json!("keys_exchanged"));
        let decoded: MatrixVerificationState = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, MatrixVerificationState::KeysExchanged);
        assert!(MatrixVerificationState::Done.is_terminal());
        assert!(MatrixVerificationState::Cancelled.is_terminal());
        assert!(MatrixVerificationState::Mismatched.is_terminal());
        assert!(!MatrixVerificationState::Ready.is_terminal());
    }

    /// Verification-flow eviction must be terminal-first. Otherwise
    /// a peer flooding fresh protocol_flow_ids fills the cap with
    /// non-terminal records and evicts the operator's pending flow
    /// at index 0 — denying the operator's verification UX.
    #[test]
    fn test_upsert_verification_record_evicts_terminal_first_at_cap() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        // Fill the cap with 1 OPERATOR-PENDING flow (non-terminal)
        // followed by (CAP-1) PEER-INITIATED flows in mixed states,
        // including some terminal so we can verify terminal-first.
        let cap = MATRIX_VERIFICATION_RECORDS_MAX;
        // First record: a non-terminal flow at index 0 (the
        // operator's). It must NOT be evicted on the next overflow.
        let (_, inserted) = upsert_verification_record(
            &state,
            "operator-flow".to_string(),
            test_owned_user_id("@operator:example.com"),
            Some("OPERDEV".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        // Add cap-2 more non-terminals; record at index 1 will be a
        // marker we can later spot when it's NOT evicted.
        for i in 0..(cap - 2) {
            upsert_verification_record(
                &state,
                format!("peer-flow-{i}"),
                format!("@peer{i}:example.com").parse().expect("user id"),
                Some(format!("PEERDEV{i}")),
                MatrixVerificationState::Requested,
            )
            .unwrap_applied();
        }
        // Add one TERMINAL record at the end (the SECOND-to-last,
        // since we add one more terminal to ensure terminal eviction).
        upsert_verification_record(
            &state,
            "old-terminal".to_string(),
            test_owned_user_id("@cancelled:example.com"),
            Some("DEVTERM".to_string()),
            MatrixVerificationState::Cancelled,
        )
        .unwrap_applied();
        // Cap is now reached. Insert one more — this triggers
        // eviction. The OLDEST-TERMINAL is "old-terminal"; should be
        // dropped. Operator's flow stays.
        let (_, inserted) = upsert_verification_record(
            &state,
            "trigger-evict".to_string(),
            test_owned_user_id("@new:example.com"),
            Some("DEVNEW".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert!(inserted);
        let guard = state.read();
        let flow_ids: Vec<&str> = guard
            .verifications
            .iter()
            .map(|f| f.protocol_flow_id.as_str())
            .collect();
        assert!(
            flow_ids.contains(&"operator-flow"),
            "operator's pending flow MUST NOT be evicted under peer flood"
        );
        assert!(
            !flow_ids.contains(&"old-terminal"),
            "oldest terminal record MUST be evicted before any non-terminal"
        );
    }

    /// Multi-call cumulative cap-eviction with a terminal-rich
    /// stream. As long as terminal records exist in the buffer at
    /// eviction time, the operator's non-terminal flow at index 0
    /// must NEVER be evicted. The all-non-terminal case is the
    /// documented backstop scenario where TTL pruning protects
    /// the flow; this test explicitly avoids that scenario by
    /// keeping the buffer terminal-rich (every insert is terminal
    /// after the operator's flow goes in).
    #[test]
    fn test_upsert_verification_record_multi_call_cumulative_eviction_preserves_operator_flow() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let cap = MATRIX_VERIFICATION_RECORDS_MAX;

        upsert_verification_record(
            &state,
            "operator-flow".to_string(),
            test_owned_user_id("@operator:example.com"),
            Some("OPERDEV".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();

        // Drive 3*cap upserts of TERMINAL records (peer-initiated
        // verifications that immediately resolve to Cancelled).
        // Each insert above cap triggers eviction; with only
        // terminals available, the eviction policy drops the
        // oldest terminal and never touches the operator's
        // non-terminal at index 0.
        for i in 0..(3 * cap) {
            upsert_verification_record(
                &state,
                format!("peer-flow-{i}"),
                format!("@peer{i}:example.com").parse().expect("user id"),
                Some(format!("DEV{i}")),
                MatrixVerificationState::Cancelled,
            )
            .unwrap_applied();
        }

        let guard = state.read();
        assert!(
            guard.verifications.len() <= cap,
            "verification cap must hold under sustained upserts: got {} > {cap}",
            guard.verifications.len(),
        );
        let has_operator = guard
            .verifications
            .iter()
            .any(|f| f.protocol_flow_id == "operator-flow");
        assert!(
            has_operator,
            "operator's pending flow at index 0 must survive cumulative terminal-rich \
             cap eviction — terminal-first eviction policy must protect index 0"
        );
    }

    /// All-terminal cap-eviction: when every record in the buffer
    /// is terminal, eviction drops the oldest terminal (which is
    /// the oldest record overall — same outcome). Pin that the
    /// eviction does NOT panic and that the buffer stays bounded.
    #[test]
    fn test_upsert_verification_record_all_terminal_at_cap_drops_oldest() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let cap = MATRIX_VERIFICATION_RECORDS_MAX;
        for i in 0..(cap + 5) {
            upsert_verification_record(
                &state,
                format!("flow-{i}"),
                format!("@user{i}:example.com").parse().expect("user id"),
                Some(format!("DEV{i}")),
                MatrixVerificationState::Cancelled,
            )
            .unwrap_applied();
        }
        let guard = state.read();
        assert_eq!(guard.verifications.len(), cap);
        // Oldest 5 records (flow-0 through flow-4) should be
        // evicted; flow-5 onward should remain.
        for i in 0..5 {
            let id = format!("flow-{i}");
            assert!(
                !guard.verifications.iter().any(|f| f.protocol_flow_id == id),
                "flow-{i} (oldest) should have been evicted"
            );
        }
        for i in 5..(cap + 5) {
            let id = format!("flow-{i}");
            assert!(
                guard.verifications.iter().any(|f| f.protocol_flow_id == id),
                "flow-{i} (recent) should still be in the buffer"
            );
        }
    }

    #[test]
    fn test_upsert_verification_record_refuses_when_all_records_are_active() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let cap = MATRIX_VERIFICATION_RECORDS_MAX;
        for i in 0..cap {
            upsert_verification_record(
                &state,
                format!("active-flow-{i}"),
                format!("@user{i}:example.com").parse().expect("user id"),
                Some(format!("DEV{i}")),
                MatrixVerificationState::KeysExchanged,
            )
            .unwrap_applied();
        }

        let result = upsert_verification_record(
            &state,
            "new-peer-flow".to_string(),
            test_owned_user_id("@new:example.com"),
            Some("NEWDEV".to_string()),
            MatrixVerificationState::Requested,
        );

        assert!(matches!(result, VerificationRecordUpsert::RejectedAtCap));
        let guard = state.read();
        assert_eq!(guard.verifications.len(), cap);
        assert!(
            guard
                .verifications
                .iter()
                .any(|f| f.protocol_flow_id == "active-flow-0"),
            "active ceremonies must not be evicted to admit a fresh peer request"
        );
        assert!(
            !guard
                .verifications
                .iter()
                .any(|f| f.protocol_flow_id == "new-peer-flow"),
            "fresh peer request must not be recorded when every capped slot is active"
        );
    }

    #[test]
    fn test_upsert_verification_record_same_peer_eviction_uses_typed_user_id() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let raw_plain = test_owned_user_id("@alice:example.com");
        let other_user = test_owned_user_id("@alice2:example.com");

        upsert_verification_record(
            &state,
            "victim-flow".to_string(),
            raw_plain.clone(),
            Some("VICTIM".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();

        for i in 1..MATRIX_VERIFICATION_RECORDS_MAX {
            upsert_verification_record(
                &state,
                format!("active-flow-{i}"),
                format!("@peer{i}:example.com").parse().expect("user id"),
                Some(format!("ACTIVE{i}")),
                MatrixVerificationState::KeysExchanged,
            )
            .unwrap_applied();
        }

        let result = upsert_verification_record(
            &state,
            "incoming-flow".to_string(),
            other_user.clone(),
            Some("INCOMING".to_string()),
            MatrixVerificationState::Requested,
        );

        assert!(matches!(result, VerificationRecordUpsert::RejectedAtCap));
        let guard = state.read();
        assert!(
            guard.verifications.iter().any(|flow| {
                flow.raw_user_id == raw_plain && flow.protocol_flow_id == "victim-flow"
            }),
            "a different typed user ID must not evict the victim user's requested flow"
        );
        assert!(
            !guard
                .verifications
                .iter()
                .any(|flow| flow.raw_user_id == other_user),
            "new flow must be rejected rather than evicting a different typed user's flow"
        );
    }

    /// Exactly-at-cap: no eviction happens on the boundary insert.
    /// The cap is `MATRIX_VERIFICATION_RECORDS_MAX` items; the
    /// `cap+1`-th insert triggers the first eviction. Pin that
    /// exactly-cap is steady-state, no flapping.
    #[test]
    fn test_upsert_verification_record_at_cap_does_not_evict() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let cap = MATRIX_VERIFICATION_RECORDS_MAX;
        for i in 0..cap {
            upsert_verification_record(
                &state,
                format!("flow-{i}"),
                format!("@user{i}:example.com").parse().expect("user id"),
                Some(format!("DEV{i}")),
                MatrixVerificationState::Requested,
            )
            .unwrap_applied();
        }
        let guard = state.read();
        assert_eq!(
            guard.verifications.len(),
            cap,
            "exactly-cap insert count must produce exactly-cap buffer length"
        );
        // All flows must be present (no evictions yet).
        for i in 0..cap {
            let id = format!("flow-{i}");
            assert!(
                guard.verifications.iter().any(|f| f.protocol_flow_id == id),
                "flow-{i} must still be in the buffer at exactly-cap"
            );
        }
    }

    /// Verify-action against a flow already in `Cancelled`/`Done`/
    /// `Mismatched` must surface `MatrixError::VerificationCancelled`,
    /// NOT a generic Verification error or a state-transition success.
    /// The CLI routes 410 Gone on this variant, signaling the operator
    /// to start a new flow rather than retry. This test pins the
    /// classifier's terminal-state guard at the helper level by
    /// stamping a verification record into runtime state and reading
    /// back the post-cancel snapshot.
    #[test]
    fn test_upsert_verification_record_preserves_terminal_state_after_cancel() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        // Initial flow: Requested.
        upsert_verification_record(
            &state,
            "flow-1".to_string(),
            test_owned_user_id("@peer:example.com"),
            Some("DEVPEER".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        // Update to Cancelled (terminal). State machine must store
        // the terminal state so a later Confirm can see it.
        let (rec, _) = upsert_verification_record(
            &state,
            "flow-1".to_string(),
            test_owned_user_id("@peer:example.com"),
            Some("DEVPEER".to_string()),
            MatrixVerificationState::Cancelled,
        )
        .unwrap_applied();
        assert_eq!(rec.state, MatrixVerificationState::Cancelled);

        // The exact `apply_verification_action` plumbing requires
        // an SDK `VerificationRequest` handle; the testable surface
        // is the state lookup that `apply_verification_action`
        // would consult. Pin that the cancelled record is
        // discoverable by `protocol_flow_id` so the action path
        // can return `VerificationCancelled`.
        let guard = state.read();
        let found = guard
            .verifications
            .iter()
            .find(|f| f.protocol_flow_id == "flow-1")
            .expect("flow-1 must exist");
        assert!(found.state.is_terminal());
        assert_eq!(found.state, MatrixVerificationState::Cancelled);
    }

    #[test]
    fn test_verification_terminal_guard_rejects_accept_and_confirm_but_allows_cancel() {
        for terminal_state in [
            MatrixVerificationState::Cancelled,
            MatrixVerificationState::Done,
            MatrixVerificationState::Mismatched,
        ] {
            for action in [
                MatrixVerificationAction::Accept,
                MatrixVerificationAction::Confirm { matches: true },
            ] {
                let err =
                    guard_verification_action_terminal_state("flow-1", &action, &terminal_state)
                        .expect_err(
                        "accept/confirm against terminal flow must be rejected before SDK lookup",
                    );
                assert!(matches!(
                    err,
                    MatrixError::VerificationCancelled {
                        flow_id,
                        state,
                    } if flow_id == "flow-1" && state == terminal_state
                ));
            }

            guard_verification_action_terminal_state(
                "flow-1",
                &MatrixVerificationAction::Cancel,
                &terminal_state,
            )
            .expect("cancel against terminal flow is idempotent");
        }
    }

    /// `to-device` verification events from neither the
    /// configured user nor the auto-join allowlist must be dropped
    /// without entering the verification record store. Otherwise a
    /// hostile peer can spam 256 fresh transaction_ids and evict
    /// the operator's legitimate flow at index 0 (the cap-eviction
    /// fallback path).
    ///
    /// The handler is async and consumes an SDK event type that's
    /// awkward to construct in unit tests, so this test exercises
    /// the GATE policy directly via the helper
    /// `MatrixAutoJoinConfig::allows_user` and the self-equality
    /// check that the handler uses. A regression that loosens the
    /// gate (e.g. removes the `allows_user` arm) would not trip
    /// this test, but a regression that breaks the helpers
    /// themselves would, and a static-analysis pin against the
    /// handler body catches the gate-removal class of refactor.
    #[test]
    fn test_handle_to_device_verification_gate_helpers_reject_unallowed_peer() {
        let config = matrix_test_config(false);
        // Non-allowlisted peer, not the configured user.
        assert!(
            !config.auto_join.allows_user("@hostile-peer:evil.com"),
            "default test config must not allowlist arbitrary peers"
        );
        // Configured user is `@cara:example.com` per matrix_test_config.
        assert_eq!(config.user_id, "@cara:example.com");

        // Pin the source body — the handler's gate must combine
        // self-equality OR allowlist; a refactor that drops either
        // arm breaks the contract.
        let body = matrix_rs_fn_body("async fn handle_to_device_event");
        let body = body.as_str();
        assert!(
            body.contains("matrix_user_ids_equal(sender, &config.user_id)")
                || body.contains("matrix_user_ids_equal(\n"),
            "handle_to_device_event must check self-verification via matrix_user_ids_equal"
        );
        assert!(
            body.contains("auto_join.allows_user"),
            "handle_to_device_event must consult the allowlist for non-self peers"
        );
        assert!(
            body.contains("to-device verification event dropped"),
            "handle_to_device_event must drop unallowed peers (warn-log marker present)"
        );
        let classifier = matrix_rs_fn_body("fn matrix_to_device_verification_sender_and_kind");
        let classifier = classifier.as_str();
        for event_type in [
            "m.key.verification.start",
            "m.key.verification.ready",
            "m.key.verification.key",
            "m.key.verification.mac",
        ] {
            assert!(
                classifier.contains(event_type),
                "to-device verification classifier must include {event_type}"
            );
        }
    }
}
