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
//!
//! TODO(Package 1 coordination): The cron handlers need access to a CronScheduler
//! instance on WsServerState. When integrating:
//! 1. Add `cron_scheduler: Arc<CronScheduler>` to WsServerState
//! 2. Update dispatch_method calls to pass state:
//!    - `"cron.status" => handle_cron_status(state)`
//!    - `"cron.list" => handle_cron_list(state, params)`
//!    - `"cron.add" => handle_cron_add(state, params)`
//!    - etc.
//! 3. Update handler signatures to take `state: &WsServerState`

use serde_json::{json, Value};
use uuid::Uuid;

use super::super::*;

// Re-export types for use by other modules
pub use crate::cron::{
    CronError, CronEvent, CronEventAction, CronIsolation, CronJob, CronJobCreate, CronJobPatch,
    CronJobState, CronJobStatus, CronPayload, CronRemoveResult, CronRunLogEntry, CronRunMode,
    CronRunReason, CronRunResult, CronSchedule, CronScheduler, CronSessionTarget, CronStatus,
    CronStoreFile, CronWakeMode,
};

/// Get the cron scheduler status.
pub(super) fn handle_cron_status() -> Result<Value, ErrorShape> {
    // TODO(Package 1 coordination): Change signature to take state
    // and use: state.cron_scheduler.status()
    Ok(json!({
        "enabled": true,
        "storePath": null,
        "jobs": 0,
        "nextRunAtMs": null
    }))
}

/// List all cron jobs.
pub(super) fn handle_cron_list() -> Result<Value, ErrorShape> {
    // TODO(Package 1 coordination): Change signature to take (state, params)
    // and use: state.cron_scheduler.list(include_disabled)
    Ok(json!({
        "jobs": []
    }))
}

/// Add a new cron job.
pub(super) fn handle_cron_add(params: Option<&Value>) -> Result<Value, ErrorShape> {
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

    let schedule = parse_schedule(params.get("schedule"))?;
    let payload = parse_payload(params.get("payload"))?;

    let job_id = Uuid::new_v4().to_string();
    let now = now_ms();

    let next_run_at_ms = compute_next_run(&schedule, now);

    // TODO(Package 1 coordination): Use state.cron_scheduler.add() instead
    // and broadcast_event(state, "cron", json!({...}))

    Ok(json!({
        "ok": true,
        "job": {
            "id": job_id,
            "name": name,
            "enabled": params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
            "schedule": schedule,
            "payload": payload,
            "createdAtMs": now,
            "updatedAtMs": now,
            "sessionTarget": params.get("sessionTarget").and_then(|v| v.as_str()).unwrap_or("main"),
            "wakeMode": params.get("wakeMode").and_then(|v| v.as_str()).unwrap_or("now"),
            "state": {
                "nextRunAtMs": next_run_at_ms
            }
        }
    }))
}

/// Update an existing cron job.
pub(super) fn handle_cron_update(params: Option<&Value>) -> Result<Value, ErrorShape> {
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

    // TODO(Package 1 coordination): Use state.cron_scheduler.update() instead

    Ok(json!({
        "ok": true,
        "jobId": job_id,
        "updated": true
    }))
}

/// Remove a cron job.
pub(super) fn handle_cron_remove(params: Option<&Value>) -> Result<Value, ErrorShape> {
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

    // TODO(Package 1 coordination): Use state.cron_scheduler.remove() instead

    Ok(json!({
        "ok": true,
        "jobId": job_id,
        "removed": true
    }))
}

/// Manually run a cron job.
pub(super) fn handle_cron_run(params: Option<&Value>) -> Result<Value, ErrorShape> {
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

    let mode = params.and_then(|v| v.get("mode")).and_then(|v| v.as_str());

    // Validate mode if provided
    if let Some(m) = mode {
        if m != "due" && m != "force" {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "mode must be 'due' or 'force'",
                None,
            ));
        }
    }

    // TODO(Package 1 coordination): Use state.cron_scheduler.run() instead

    Ok(json!({
        "ok": true,
        "jobId": job_id,
        "ran": true,
        "reason": null
    }))
}

/// Get run history for jobs.
pub(super) fn handle_cron_runs(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let job_id = params.and_then(|v| v.get("jobId")).and_then(|v| v.as_str());
    let _limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(200);

    // TODO(Package 1 coordination): Use state.cron_scheduler.runs() instead

    Ok(json!({
        "runs": [],
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

/// Parse isolation settings from JSON.
#[allow(dead_code)]
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

/// Compute the next run time for a schedule.
fn compute_next_run(schedule: &CronSchedule, now: u64) -> Option<u64> {
    match schedule {
        CronSchedule::At { at_ms } => {
            if *at_ms > now {
                Some(*at_ms)
            } else {
                None // Already passed
            }
        }
        CronSchedule::Every {
            every_ms,
            anchor_ms,
        } => {
            // Guard against divide-by-zero (should be validated at parse time)
            if *every_ms == 0 {
                return None;
            }
            let anchor = anchor_ms.unwrap_or(now);
            if now < anchor {
                Some(anchor)
            } else {
                let elapsed = now - anchor;
                let periods = elapsed / every_ms;
                Some(anchor + (periods + 1) * every_ms)
            }
        }
        CronSchedule::Cron { expr: _, tz: _ } => {
            // Cron expression parsing would require a cron library
            // For now, return a default next minute
            let next_minute = (now / 60_000 + 1) * 60_000;
            Some(next_minute)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_cron_status() {
        let result = handle_cron_status();
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["enabled"], true);
        assert_eq!(value["jobs"], 0);
    }

    #[test]
    fn test_handle_cron_list() {
        let result = handle_cron_list();
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value["jobs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_handle_cron_add_requires_params() {
        let result = handle_cron_add(None);
        assert!(result.is_err());

        let params = json!({});
        let result = handle_cron_add(Some(&params));
        assert!(result.is_err()); // Missing name
    }

    #[test]
    fn test_handle_cron_add_validates_name() {
        let params = json!({
            "name": "",
            "schedule": { "kind": "at", "atMs": 1000 },
            "payload": { "kind": "systemEvent", "text": "test" }
        });
        let result = handle_cron_add(Some(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_cron_add_success() {
        let params = json!({
            "name": "Test Job",
            "schedule": { "kind": "every", "everyMs": 60000 },
            "payload": { "kind": "systemEvent", "text": "Hello!" }
        });
        let result = handle_cron_add(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["job"]["name"], "Test Job");
        assert!(value["job"]["id"].as_str().is_some());
    }

    #[test]
    fn test_handle_cron_update_requires_job_id() {
        let result = handle_cron_update(None);
        assert!(result.is_err());

        let params = json!({ "jobId": "" });
        let result = handle_cron_update(Some(&params));
        assert!(result.is_err());

        let params = json!({ "jobId": "test-id" });
        let result = handle_cron_update(Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cron_remove_requires_job_id() {
        let result = handle_cron_remove(None);
        assert!(result.is_err());

        let params = json!({ "jobId": "" });
        let result = handle_cron_remove(Some(&params));
        assert!(result.is_err());

        let params = json!({ "jobId": "test-id" });
        let result = handle_cron_remove(Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cron_run_requires_job_id() {
        let result = handle_cron_run(None);
        assert!(result.is_err());

        let params = json!({ "jobId": "" });
        let result = handle_cron_run(Some(&params));
        assert!(result.is_err());

        let params = json!({ "jobId": "test-id" });
        let result = handle_cron_run(Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cron_run_validates_mode() {
        let params = json!({ "jobId": "test-id", "mode": "invalid" });
        let result = handle_cron_run(Some(&params));
        assert!(result.is_err());

        let params = json!({ "jobId": "test-id", "mode": "force" });
        let result = handle_cron_run(Some(&params));
        assert!(result.is_ok());

        let params = json!({ "jobId": "test-id", "mode": "due" });
        let result = handle_cron_run(Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cron_runs() {
        let result = handle_cron_runs(None);
        assert!(result.is_ok());

        let params = json!({ "jobId": "test-id", "limit": 50 });
        let result = handle_cron_runs(Some(&params));
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["jobId"], "test-id");
    }

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
    fn test_compute_next_run_every_zero_returns_none() {
        // Defensive guard: even if everyMs=0 somehow gets through validation,
        // compute_next_run should return None instead of panicking
        let schedule = CronSchedule::Every {
            every_ms: 0,
            anchor_ms: None,
        };
        assert_eq!(compute_next_run(&schedule, 1000), None);
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
    fn test_compute_next_run_at() {
        let now = 1000;

        // Future time
        let schedule = CronSchedule::At { at_ms: 2000 };
        assert_eq!(compute_next_run(&schedule, now), Some(2000));

        // Past time
        let schedule = CronSchedule::At { at_ms: 500 };
        assert_eq!(compute_next_run(&schedule, now), None);
    }

    #[test]
    fn test_compute_next_run_every() {
        let now = 1000;

        // Simple interval
        let schedule = CronSchedule::Every {
            every_ms: 100,
            anchor_ms: None,
        };
        let next = compute_next_run(&schedule, now).unwrap();
        assert!(next > now);
        assert!(next <= now + 100);

        // With anchor
        let schedule = CronSchedule::Every {
            every_ms: 100,
            anchor_ms: Some(950),
        };
        let next = compute_next_run(&schedule, now).unwrap();
        assert_eq!(next, 1050); // 950 + 100
    }
}
