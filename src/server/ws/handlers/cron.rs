//! Cron handlers.
//!
//! This module implements the cron scheduler methods:
//! - cron.status: Get scheduler status
//! - cron.list: List all jobs
//! - cron.add: Add a new job
//! - cron.update: Update an existing job
//! - cron.remove: Remove a job
//! - cron.run: Manually run a job
//! - cron.runs: Get run history

use serde_json::{json, Value};

use super::super::*;

// Re-export types for use by other modules
pub use crate::cron::{
    CronError, CronEvent, CronEventAction, CronIsolation, CronJob, CronJobCreate, CronJobPatch,
    CronJobState, CronJobStatus, CronPayload, CronRemoveResult, CronRunLogEntry, CronRunMode,
    CronRunReason, CronRunResult, CronSchedule, CronScheduler, CronSessionTarget, CronStatus,
    CronStoreFile, CronWakeMode,
};

/// Get the cron scheduler status.
pub(super) fn handle_cron_status(state: &WsServerState) -> Result<Value, ErrorShape> {
    let status = state.cron_scheduler.status();
    Ok(json!({
        "enabled": status.enabled,
        "storePath": status.store_path,
        "jobs": status.jobs,
        "nextRunAtMs": status.next_run_at_ms
    }))
}

/// List all cron jobs.
pub(super) fn handle_cron_list(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let include_disabled = params
        .and_then(|p| p.get("includeDisabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let jobs = state.cron_scheduler.list(include_disabled);
    let jobs_json: Vec<Value> = jobs
        .iter()
        .map(|j| serde_json::to_value(j).unwrap_or(json!({})))
        .collect();

    Ok(json!({
        "jobs": jobs_json
    }))
}

/// Add a new cron job.
pub(super) fn handle_cron_add(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let params =
        params.ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "params required", None))?;

    // Parse required fields
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;

    if name.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "name cannot be empty",
            None,
        ));
    }

    if name.len() > 256 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "name too long (max 256 characters)",
            None,
        ));
    }

    let schedule = parse_schedule(params.get("schedule"))?;
    let payload = parse_payload(params.get("payload"))?;

    // Parse optional fields
    let agent_id = params
        .get("agentId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let description = params
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let enabled = params
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let delete_after_run = params.get("deleteAfterRun").and_then(|v| v.as_bool());
    let session_target = parse_session_target(params.get("sessionTarget"));
    let wake_mode = parse_wake_mode(params.get("wakeMode"));
    let isolation = params.get("isolation").and_then(|v| parse_isolation(v));

    let input = CronJobCreate {
        name: name.to_string(),
        agent_id,
        description,
        enabled,
        delete_after_run,
        schedule,
        session_target,
        wake_mode,
        payload,
        isolation,
    };

    let job = state.cron_scheduler.add(input).map_err(|e| match e {
        CronError::LimitExceeded(max) => error_shape(
            ERROR_INVALID_REQUEST,
            &format!("cron job limit exceeded (max {})", max),
            None,
        ),
        _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
    })?;

    // Broadcast cron.scheduled event
    broadcast_cron_event(
        state,
        &job.id,
        "scheduled",
        None,
        Some(json!({
            "jobId": job.id,
            "name": job.name,
            "nextRunAtMs": job.state.next_run_at_ms
        })),
    );

    Ok(json!({
        "ok": true,
        "job": serde_json::to_value(&job).unwrap_or(json!({}))
    }))
}

/// Update an existing cron job.
pub(super) fn handle_cron_update(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let params =
        params.ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "params required", None))?;

    let job_id = params
        .get("jobId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "jobId is required", None))?;

    if job_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "jobId cannot be empty",
            None,
        ));
    }

    // Validate name length if provided
    if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
        if name.len() > 256 {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "name too long (max 256 characters)",
                None,
            ));
        }
    }

    // Build patch from params
    let patch = CronJobPatch {
        name: params
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        agent_id: params
            .get("agentId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        description: params
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        enabled: params.get("enabled").and_then(|v| v.as_bool()),
        delete_after_run: params.get("deleteAfterRun").and_then(|v| v.as_bool()),
        schedule: match params.get("schedule") {
            Some(v) => Some(parse_schedule(Some(v))?),
            None => None,
        },
        session_target: params
            .get("sessionTarget")
            .map(|_| parse_session_target(params.get("sessionTarget"))),
        wake_mode: params
            .get("wakeMode")
            .map(|_| parse_wake_mode(params.get("wakeMode"))),
        payload: match params.get("payload") {
            Some(v) => Some(parse_payload(Some(v))?),
            None => None,
        },
        isolation: params.get("isolation").and_then(|v| parse_isolation(v)),
    };

    let job = state
        .cron_scheduler
        .update(job_id, patch)
        .map_err(|e| match e {
            CronError::JobNotFound(_) => error_shape(
                ERROR_INVALID_REQUEST,
                "job not found",
                Some(json!({ "jobId": job_id })),
            ),
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    // Broadcast cron.scheduled event (job was rescheduled)
    broadcast_cron_event(
        state,
        &job.id,
        "scheduled",
        None,
        Some(json!({
            "jobId": job.id,
            "name": job.name,
            "nextRunAtMs": job.state.next_run_at_ms,
            "action": "updated"
        })),
    );

    Ok(json!({
        "ok": true,
        "jobId": job.id,
        "updated": true,
        "job": serde_json::to_value(&job).unwrap_or(json!({}))
    }))
}

/// Remove a cron job.
pub(super) fn handle_cron_remove(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let job_id = params
        .and_then(|v| v.get("jobId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "jobId is required", None))?;

    if job_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "jobId cannot be empty",
            None,
        ));
    }

    let result = state.cron_scheduler.remove(job_id);

    Ok(json!({
        "ok": result.ok,
        "jobId": job_id,
        "removed": result.removed
    }))
}

/// Manually run a cron job.
pub(super) fn handle_cron_run(
    state: Arc<WsServerState>,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let job_id = params
        .and_then(|v| v.get("jobId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "jobId is required", None))?;

    if job_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "jobId cannot be empty",
            None,
        ));
    }

    let mode_str = params.and_then(|v| v.get("mode")).and_then(|v| v.as_str());

    // Validate mode if provided
    let mode = if let Some(m) = mode_str {
        match m {
            "due" => Some(CronRunMode::Due),
            "force" => Some(CronRunMode::Force),
            _ => {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "mode must be 'due' or 'force'",
                    None,
                ));
            }
        }
    } else {
        None
    };

    // Get job info before running for event
    let job = state.cron_scheduler.get(job_id);

    let result = state
        .cron_scheduler
        .run(job_id, mode)
        .map_err(|e| match e {
            CronError::JobNotFound(_) => error_shape(
                ERROR_INVALID_REQUEST,
                "job not found",
                Some(json!({ "jobId": job_id })),
            ),
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    if result.ran {
        // Broadcast cron.started event
        broadcast_cron_event(
            &state,
            job_id,
            "started",
            None,
            Some(json!({
                "jobId": job_id,
                "name": job.as_ref().map(|j| j.name.as_str()),
                "manual": true
            })),
        );

        // Spawn async payload execution if there's a payload
        if let Some(payload) = result.payload.clone() {
            let state_clone = state.clone();
            let job_id_owned = job_id.to_string();
            let job_name = job.as_ref().map(|j| j.name.clone());
            tokio::spawn(async move {
                let start = std::time::Instant::now();
                let outcome =
                    crate::cron::executor::execute_payload(&job_id_owned, &payload, &state_clone)
                        .await;
                let duration_ms = start.elapsed().as_millis() as u64;

                let (status, error) = match outcome {
                    Ok(_) => (CronJobStatus::Ok, None),
                    Err(e) => (CronJobStatus::Error, Some(e)),
                };

                if let Err(e) = state_clone.cron_scheduler.mark_run_finished(
                    &job_id_owned,
                    status,
                    duration_ms,
                    error,
                ) {
                    tracing::warn!(
                        job_id = %job_id_owned,
                        error = %e,
                        "failed to mark cron run finished"
                    );
                }

                // Broadcast cron.completed event
                broadcast_cron_event(
                    &state_clone,
                    &job_id_owned,
                    "completed",
                    None,
                    Some(json!({
                        "jobId": &job_id_owned,
                        "name": job_name,
                        "status": format!("{:?}", status),
                        "durationMs": duration_ms
                    })),
                );
            });
        }
    }

    Ok(json!({
        "ok": result.ok,
        "jobId": job_id,
        "ran": result.ran,
        "reason": result.reason
    }))
}

/// Get run history for jobs.
pub(super) fn handle_cron_runs(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let job_id = params.and_then(|v| v.get("jobId")).and_then(|v| v.as_str());
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).min(5000)); // Cap at 5000 at handler level

    let runs = state.cron_scheduler.runs(job_id, limit);
    let runs_json: Vec<Value> = runs
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(json!({})))
        .collect();

    Ok(json!({
        "runs": runs_json,
        "jobId": job_id
    }))
}

/// Parse a schedule from JSON.
fn parse_schedule(value: Option<&Value>) -> Result<CronSchedule, ErrorShape> {
    let value =
        value.ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "schedule is required", None))?;

    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "schedule.kind is required", None))?;

    match kind {
        "at" => {
            let at_ms = value.get("atMs").and_then(|v| v.as_u64()).ok_or_else(|| {
                error_shape(
                    ERROR_INVALID_REQUEST,
                    "schedule.atMs is required for 'at' schedule",
                    None,
                )
            })?;
            Ok(CronSchedule::At { at_ms })
        }
        "every" => {
            let every_ms = value
                .get("everyMs")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| {
                    error_shape(
                        ERROR_INVALID_REQUEST,
                        "schedule.everyMs is required for 'every' schedule",
                        None,
                    )
                })?;
            // Validate everyMs >= 1 to prevent divide-by-zero in compute_next_run
            if every_ms < 1 {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "schedule.everyMs must be at least 1",
                    None,
                ));
            }
            let anchor_ms = value.get("anchorMs").and_then(|v| v.as_u64());
            Ok(CronSchedule::Every {
                every_ms,
                anchor_ms,
            })
        }
        "cron" => {
            let expr = value.get("expr").and_then(|v| v.as_str()).ok_or_else(|| {
                error_shape(
                    ERROR_INVALID_REQUEST,
                    "schedule.expr is required for 'cron' schedule",
                    None,
                )
            })?;
            let tz = value
                .get("tz")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(CronSchedule::Cron {
                expr: expr.to_string(),
                tz,
            })
        }
        _ => Err(error_shape(
            ERROR_INVALID_REQUEST,
            "schedule.kind must be 'at', 'every', or 'cron'",
            None,
        )),
    }
}

/// Parse a payload from JSON.
fn parse_payload(value: Option<&Value>) -> Result<CronPayload, ErrorShape> {
    let value =
        value.ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "payload is required", None))?;

    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "payload.kind is required", None))?;

    match kind {
        "systemEvent" => {
            let text = value.get("text").and_then(|v| v.as_str()).ok_or_else(|| {
                error_shape(
                    ERROR_INVALID_REQUEST,
                    "payload.text is required for 'systemEvent' payload",
                    None,
                )
            })?;
            Ok(CronPayload::SystemEvent {
                text: text.to_string(),
            })
        }
        "agentTurn" => {
            let message = value
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    error_shape(
                        ERROR_INVALID_REQUEST,
                        "payload.message is required for 'agentTurn' payload",
                        None,
                    )
                })?;
            Ok(CronPayload::AgentTurn {
                message: message.to_string(),
                model: value
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                thinking: value
                    .get("thinking")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                timeout_seconds: value
                    .get("timeoutSeconds")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32),
                allow_unsafe_external_content: value
                    .get("allowUnsafeExternalContent")
                    .and_then(|v| v.as_bool()),
                deliver: value.get("deliver").and_then(|v| v.as_bool()),
                channel: value
                    .get("channel")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                to: value
                    .get("to")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                best_effort_deliver: value.get("bestEffortDeliver").and_then(|v| v.as_bool()),
            })
        }
        _ => Err(error_shape(
            ERROR_INVALID_REQUEST,
            "payload.kind must be 'systemEvent' or 'agentTurn'",
            None,
        )),
    }
}

/// Parse session target from JSON.
fn parse_session_target(value: Option<&Value>) -> CronSessionTarget {
    value
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "isolated" => CronSessionTarget::Isolated,
            _ => CronSessionTarget::Main,
        })
        .unwrap_or(CronSessionTarget::Main)
}

/// Parse wake mode from JSON.
fn parse_wake_mode(value: Option<&Value>) -> CronWakeMode {
    value
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "next-heartbeat" => CronWakeMode::NextHeartbeat,
            _ => CronWakeMode::Now,
        })
        .unwrap_or(CronWakeMode::Now)
}

/// Parse isolation settings from JSON.
fn parse_isolation(value: &Value) -> Option<CronIsolation> {
    if !value.is_object() {
        return None;
    }

    Some(CronIsolation {
        post_to_main_prefix: value
            .get("postToMainPrefix")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        post_to_main_mode: value
            .get("postToMainMode")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        post_to_main_max_chars: value
            .get("postToMainMaxChars")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_schedule_at() {
        let value = json!({ "kind": "at", "atMs": 1234567890 });
        let schedule = parse_schedule(Some(&value)).unwrap();
        match schedule {
            CronSchedule::At { at_ms } => assert_eq!(at_ms, 1234567890),
            _ => panic!("Expected At schedule"),
        }
    }

    #[test]
    fn test_parse_schedule_every() {
        let value = json!({ "kind": "every", "everyMs": 60000, "anchorMs": 1000 });
        let schedule = parse_schedule(Some(&value)).unwrap();
        match schedule {
            CronSchedule::Every {
                every_ms,
                anchor_ms,
            } => {
                assert_eq!(every_ms, 60000);
                assert_eq!(anchor_ms, Some(1000));
            }
            _ => panic!("Expected Every schedule"),
        }
    }

    #[test]
    fn test_parse_schedule_cron() {
        let value = json!({ "kind": "cron", "expr": "0 9 * * *", "tz": "America/New_York" });
        let schedule = parse_schedule(Some(&value)).unwrap();
        match schedule {
            CronSchedule::Cron { expr, tz } => {
                assert_eq!(expr, "0 9 * * *");
                assert_eq!(tz, Some("America/New_York".to_string()));
            }
            _ => panic!("Expected Cron schedule"),
        }
    }

    #[test]
    fn test_parse_schedule_invalid() {
        let value = json!({ "kind": "invalid" });
        let result = parse_schedule(Some(&value));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_schedule_every_rejects_zero() {
        // everyMs=0 would cause divide-by-zero in compute_next_run
        let value = json!({ "kind": "every", "everyMs": 0 });
        let result = parse_schedule(Some(&value));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message, "schedule.everyMs must be at least 1");
    }

    #[test]
    fn test_parse_payload_system_event() {
        let value = json!({ "kind": "systemEvent", "text": "Hello" });
        let payload = parse_payload(Some(&value)).unwrap();
        match payload {
            CronPayload::SystemEvent { text } => assert_eq!(text, "Hello"),
            _ => panic!("Expected SystemEvent payload"),
        }
    }

    #[test]
    fn test_parse_payload_agent_turn() {
        let value = json!({
            "kind": "agentTurn",
            "message": "Do something",
            "model": "claude-3-opus",
            "deliver": true
        });
        let payload = parse_payload(Some(&value)).unwrap();
        match payload {
            CronPayload::AgentTurn {
                message,
                model,
                deliver,
                ..
            } => {
                assert_eq!(message, "Do something");
                assert_eq!(model, Some("claude-3-opus".to_string()));
                assert_eq!(deliver, Some(true));
            }
            _ => panic!("Expected AgentTurn payload"),
        }
    }

    #[test]
    fn test_parse_isolation() {
        let value = json!({
            "postToMainPrefix": "[Cron]",
            "postToMainMode": "summary",
            "postToMainMaxChars": 5000
        });
        let isolation = parse_isolation(&value).unwrap();
        assert_eq!(isolation.post_to_main_prefix, Some("[Cron]".to_string()));
        assert_eq!(isolation.post_to_main_mode, Some("summary".to_string()));
        assert_eq!(isolation.post_to_main_max_chars, Some(5000));
    }

    #[test]
    fn test_parse_session_target() {
        assert_eq!(parse_session_target(None), CronSessionTarget::Main);
        assert_eq!(
            parse_session_target(Some(&json!("main"))),
            CronSessionTarget::Main
        );
        assert_eq!(
            parse_session_target(Some(&json!("isolated"))),
            CronSessionTarget::Isolated
        );
    }

    #[test]
    fn test_parse_wake_mode() {
        assert_eq!(parse_wake_mode(None), CronWakeMode::Now);
        assert_eq!(parse_wake_mode(Some(&json!("now"))), CronWakeMode::Now);
        assert_eq!(
            parse_wake_mode(Some(&json!("next-heartbeat"))),
            CronWakeMode::NextHeartbeat
        );
    }
}
