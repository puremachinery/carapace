//! Cron scheduler system.
//!
//! This module provides a cron-like job scheduling system that supports:
//! - One-shot jobs (run at specific time)
//! - Interval jobs (run every N milliseconds)
//! - Cron expression jobs (run on cron schedule with optional timezone)
//!
//! Jobs can execute either in the main session or in isolated sessions,
//! and can deliver messages to various channels.

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Schedule specification for a cron job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CronSchedule {
    /// Run at a specific Unix timestamp (one-shot).
    #[serde(rename = "at")]
    At {
        /// The timestamp in milliseconds when the job should run.
        #[serde(rename = "atMs")]
        at_ms: u64,
    },
    /// Run every N milliseconds.
    #[serde(rename = "every")]
    Every {
        /// The interval in milliseconds.
        #[serde(rename = "everyMs")]
        every_ms: u64,
        /// Optional anchor timestamp for alignment.
        #[serde(rename = "anchorMs", skip_serializing_if = "Option::is_none")]
        anchor_ms: Option<u64>,
    },
    /// Run on a cron expression schedule.
    #[serde(rename = "cron")]
    Cron {
        /// The cron expression (e.g., "0 9 * * *").
        expr: String,
        /// Optional timezone (e.g., "America/New_York").
        #[serde(skip_serializing_if = "Option::is_none")]
        tz: Option<String>,
    },
}

/// The target session for job execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CronSessionTarget {
    /// Run in the main session.
    #[default]
    Main,
    /// Run in an isolated session.
    Isolated,
}

/// How to wake the agent when a job runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CronWakeMode {
    /// Wake immediately.
    #[default]
    Now,
    /// Wake on next heartbeat.
    NextHeartbeat,
}

/// The payload/action for a cron job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CronPayload {
    /// Emit a system event with text.
    #[serde(rename = "systemEvent")]
    SystemEvent { text: String },
    /// Run an agent turn with a message.
    #[serde(rename = "agentTurn")]
    AgentTurn {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        thinking: Option<String>,
        #[serde(rename = "timeoutSeconds", skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
        #[serde(
            rename = "allowUnsafeExternalContent",
            skip_serializing_if = "Option::is_none"
        )]
        allow_unsafe_external_content: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        deliver: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to: Option<String>,
        #[serde(rename = "bestEffortDeliver", skip_serializing_if = "Option::is_none")]
        best_effort_deliver: Option<bool>,
    },
}

/// Configuration for isolated session behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronIsolation {
    /// Prefix for posting to main session.
    #[serde(rename = "postToMainPrefix", skip_serializing_if = "Option::is_none")]
    pub post_to_main_prefix: Option<String>,
    /// Mode for posting to main: "summary" or "full".
    #[serde(rename = "postToMainMode", skip_serializing_if = "Option::is_none")]
    pub post_to_main_mode: Option<String>,
    /// Max chars when posting full output.
    #[serde(rename = "postToMainMaxChars", skip_serializing_if = "Option::is_none")]
    pub post_to_main_max_chars: Option<u32>,
}

/// Runtime state of a cron job.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJobState {
    /// When the job is next scheduled to run.
    #[serde(rename = "nextRunAtMs", skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<u64>,
    /// When the job is currently running (if running).
    #[serde(rename = "runningAtMs", skip_serializing_if = "Option::is_none")]
    pub running_at_ms: Option<u64>,
    /// When the job last ran.
    #[serde(rename = "lastRunAtMs", skip_serializing_if = "Option::is_none")]
    pub last_run_at_ms: Option<u64>,
    /// Status of the last run.
    #[serde(rename = "lastStatus", skip_serializing_if = "Option::is_none")]
    pub last_status: Option<CronJobStatus>,
    /// Error message from last run (if any).
    #[serde(rename = "lastError", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Duration of last run in milliseconds.
    #[serde(rename = "lastDurationMs", skip_serializing_if = "Option::is_none")]
    pub last_duration_ms: Option<u64>,
}

/// Status of a job run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CronJobStatus {
    Ok,
    Error,
    Skipped,
}

/// A cron job definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJob {
    /// Unique identifier for the job.
    pub id: String,
    /// Optional agent ID association.
    #[serde(rename = "agentId", skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the job is enabled.
    pub enabled: bool,
    /// Whether to delete the job after it runs (one-shot).
    #[serde(rename = "deleteAfterRun", skip_serializing_if = "Option::is_none")]
    pub delete_after_run: Option<bool>,
    /// When the job was created.
    #[serde(rename = "createdAtMs")]
    pub created_at_ms: u64,
    /// When the job was last updated.
    #[serde(rename = "updatedAtMs")]
    pub updated_at_ms: u64,
    /// The schedule for when to run.
    pub schedule: CronSchedule,
    /// Where to run the job.
    #[serde(rename = "sessionTarget")]
    pub session_target: CronSessionTarget,
    /// How to wake the agent.
    #[serde(rename = "wakeMode")]
    pub wake_mode: CronWakeMode,
    /// What to do when the job runs.
    pub payload: CronPayload,
    /// Isolation settings (for isolated sessions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<CronIsolation>,
    /// Runtime state.
    pub state: CronJobState,
}

/// Input for creating a new cron job.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJobCreate {
    pub name: String,
    #[serde(rename = "agentId")]
    pub agent_id: Option<String>,
    pub description: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(rename = "deleteAfterRun")]
    pub delete_after_run: Option<bool>,
    pub schedule: CronSchedule,
    #[serde(rename = "sessionTarget", default)]
    pub session_target: CronSessionTarget,
    #[serde(rename = "wakeMode", default)]
    pub wake_mode: CronWakeMode,
    pub payload: CronPayload,
    pub isolation: Option<CronIsolation>,
}

fn default_enabled() -> bool {
    true
}

/// Patch for updating a cron job.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJobPatch {
    pub name: Option<String>,
    #[serde(rename = "agentId")]
    pub agent_id: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    #[serde(rename = "deleteAfterRun")]
    pub delete_after_run: Option<bool>,
    pub schedule: Option<CronSchedule>,
    #[serde(rename = "sessionTarget")]
    pub session_target: Option<CronSessionTarget>,
    #[serde(rename = "wakeMode")]
    pub wake_mode: Option<CronWakeMode>,
    pub payload: Option<CronPayload>,
    pub isolation: Option<CronIsolation>,
}

/// A log entry for a job run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronRunLogEntry {
    /// Timestamp of the log entry.
    pub ts: u64,
    /// The job ID.
    #[serde(rename = "jobId")]
    pub job_id: String,
    /// The action type (always "finished" for now).
    pub action: String,
    /// Status of the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<CronJobStatus>,
    /// Error message if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Summary of the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// When the run started.
    #[serde(rename = "runAtMs", skip_serializing_if = "Option::is_none")]
    pub run_at_ms: Option<u64>,
    /// How long the run took.
    #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// When the job will next run.
    #[serde(rename = "nextRunAtMs", skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<u64>,
}

/// Events emitted by the cron scheduler.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CronEvent {
    /// The job ID.
    #[serde(rename = "jobId")]
    pub job_id: String,
    /// The action that occurred.
    pub action: CronEventAction,
    /// When the job will next run (if applicable).
    #[serde(rename = "nextRunAtMs", skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<u64>,
    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Types of cron events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CronEventAction {
    Added,
    Updated,
    Removed,
    Started,
    Finished,
}

/// Store file format for persisting jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronStoreFile {
    pub version: u32,
    pub jobs: Vec<CronJob>,
}

impl Default for CronStoreFile {
    fn default() -> Self {
        Self {
            version: 1,
            jobs: Vec::new(),
        }
    }
}

/// The cron scheduler service.
#[derive(Debug)]
pub struct CronScheduler {
    enabled: bool,
    store_path: PathBuf,
    jobs: RwLock<Vec<CronJob>>,
    run_log: RwLock<Vec<CronRunLogEntry>>,
    event_tx: Option<mpsc::UnboundedSender<CronEvent>>,
}

impl CronScheduler {
    /// Create a new cron scheduler.
    pub fn new(store_path: PathBuf, enabled: bool) -> Self {
        Self {
            enabled,
            store_path,
            jobs: RwLock::new(Vec::new()),
            run_log: RwLock::new(Vec::new()),
            event_tx: None,
        }
    }

    /// Create a new in-memory cron scheduler (for testing).
    pub fn in_memory() -> Self {
        Self {
            enabled: true,
            store_path: PathBuf::from(":memory:"),
            jobs: RwLock::new(Vec::new()),
            run_log: RwLock::new(Vec::new()),
            event_tx: None,
        }
    }

    /// Set the event channel for emitting cron events.
    pub fn with_event_channel(mut self, tx: mpsc::UnboundedSender<CronEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// Check if the scheduler is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the scheduler status.
    pub fn status(&self) -> CronStatus {
        let jobs = self.jobs.read();
        let enabled_jobs = jobs.iter().filter(|j| j.enabled).count();
        let next_run_at_ms = jobs
            .iter()
            .filter(|j| j.enabled)
            .filter_map(|j| j.state.next_run_at_ms)
            .min();

        CronStatus {
            enabled: self.enabled,
            store_path: self.store_path.to_string_lossy().to_string(),
            jobs: enabled_jobs,
            next_run_at_ms,
        }
    }

    /// List all jobs.
    pub fn list(&self, include_disabled: bool) -> Vec<CronJob> {
        let jobs = self.jobs.read();
        let mut result: Vec<CronJob> = if include_disabled {
            jobs.clone()
        } else {
            jobs.iter().filter(|j| j.enabled).cloned().collect()
        };

        // Sort by next run time
        result.sort_by(|a, b| {
            let a_next = a.state.next_run_at_ms.unwrap_or(u64::MAX);
            let b_next = b.state.next_run_at_ms.unwrap_or(u64::MAX);
            a_next.cmp(&b_next)
        });

        result
    }

    /// Maximum number of cron jobs allowed.
    const MAX_JOBS: usize = 500;

    /// Add a new job.
    pub fn add(&self, input: CronJobCreate) -> Result<CronJob, CronError> {
        {
            let jobs = self.jobs.read();
            if jobs.len() >= Self::MAX_JOBS {
                return Err(CronError::LimitExceeded(Self::MAX_JOBS));
            }
        }

        let now = now_ms();
        let job_id = Uuid::new_v4().to_string();

        let next_run_at_ms = if input.enabled {
            compute_next_run(&input.schedule, now)
        } else {
            None
        };

        let job = CronJob {
            id: job_id.clone(),
            agent_id: input.agent_id,
            name: input.name,
            description: input.description,
            enabled: input.enabled,
            delete_after_run: input.delete_after_run,
            created_at_ms: now,
            updated_at_ms: now,
            schedule: input.schedule,
            session_target: input.session_target,
            wake_mode: input.wake_mode,
            payload: input.payload,
            isolation: input.isolation,
            state: CronJobState {
                next_run_at_ms,
                running_at_ms: None,
                last_run_at_ms: None,
                last_status: None,
                last_error: None,
                last_duration_ms: None,
            },
        };

        {
            let mut jobs = self.jobs.write();
            jobs.push(job.clone());
        }

        self.emit_event(CronEvent {
            job_id: job_id.clone(),
            action: CronEventAction::Added,
            next_run_at_ms: job.state.next_run_at_ms,
            details: None,
        });

        Ok(job)
    }

    /// Update an existing job.
    pub fn update(&self, id: &str, patch: CronJobPatch) -> Result<CronJob, CronError> {
        let now = now_ms();
        let mut jobs = self.jobs.write();

        let job = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| CronError::JobNotFound(id.to_string()))?;

        // Apply patch
        if let Some(name) = patch.name {
            job.name = name;
        }
        if let Some(agent_id) = patch.agent_id {
            job.agent_id = Some(agent_id);
        }
        if let Some(description) = patch.description {
            job.description = Some(description);
        }
        if let Some(enabled) = patch.enabled {
            job.enabled = enabled;
        }
        if let Some(delete_after_run) = patch.delete_after_run {
            job.delete_after_run = Some(delete_after_run);
        }
        if let Some(schedule) = patch.schedule {
            job.schedule = schedule;
        }
        if let Some(session_target) = patch.session_target {
            job.session_target = session_target;
        }
        if let Some(wake_mode) = patch.wake_mode {
            job.wake_mode = wake_mode;
        }
        if let Some(payload) = patch.payload {
            job.payload = payload;
        }
        if let Some(isolation) = patch.isolation {
            job.isolation = Some(isolation);
        }

        job.updated_at_ms = now;

        // Recompute next run time
        if job.enabled {
            job.state.next_run_at_ms = compute_next_run(&job.schedule, now);
        } else {
            job.state.next_run_at_ms = None;
            job.state.running_at_ms = None;
        }

        let job = job.clone();
        drop(jobs);

        self.emit_event(CronEvent {
            job_id: id.to_string(),
            action: CronEventAction::Updated,
            next_run_at_ms: job.state.next_run_at_ms,
            details: None,
        });

        Ok(job)
    }

    /// Remove a job.
    pub fn remove(&self, id: &str) -> CronRemoveResult {
        let mut jobs = self.jobs.write();
        let before = jobs.len();
        jobs.retain(|j| j.id != id);
        let removed = jobs.len() != before;
        drop(jobs);

        if removed {
            self.emit_event(CronEvent {
                job_id: id.to_string(),
                action: CronEventAction::Removed,
                next_run_at_ms: None,
                details: None,
            });
        }

        CronRemoveResult { ok: true, removed }
    }

    /// Manually run a job.
    pub fn run(&self, id: &str, mode: Option<CronRunMode>) -> Result<CronRunResult, CronError> {
        let mode = mode.unwrap_or(CronRunMode::Due);
        let now = now_ms();

        let mut jobs = self.jobs.write();
        let job = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| CronError::JobNotFound(id.to_string()))?;

        // Check if job is due
        let is_due = match mode {
            CronRunMode::Force => true,
            CronRunMode::Due => {
                if !job.enabled {
                    false
                } else if let Some(next_run) = job.state.next_run_at_ms {
                    now >= next_run
                } else {
                    false
                }
            }
        };

        if !is_due {
            return Ok(CronRunResult {
                ok: true,
                ran: false,
                reason: Some(CronRunReason::NotDue),
            });
        }

        // Mark as running
        job.state.running_at_ms = Some(now);

        self.emit_event(CronEvent {
            job_id: id.to_string(),
            action: CronEventAction::Started,
            next_run_at_ms: job.state.next_run_at_ms,
            details: None,
        });

        // Simulate job execution (actual execution would be async)
        let run_at_ms = now;
        let duration_ms = 0; // Would be actual duration in real implementation

        // Update job state after run
        job.state.last_run_at_ms = Some(run_at_ms);
        job.state.last_duration_ms = Some(duration_ms);
        job.state.last_status = Some(CronJobStatus::Ok);
        job.state.running_at_ms = None;

        // Compute next run time
        job.state.next_run_at_ms = compute_next_run(&job.schedule, now);

        // Record run log
        let log_entry = CronRunLogEntry {
            ts: now,
            job_id: id.to_string(),
            action: "finished".to_string(),
            status: Some(CronJobStatus::Ok),
            error: None,
            summary: None,
            run_at_ms: Some(run_at_ms),
            duration_ms: Some(duration_ms),
            next_run_at_ms: job.state.next_run_at_ms,
        };

        let job_id = id.to_string();
        let next_run = job.state.next_run_at_ms;
        drop(jobs);

        {
            let mut run_log = self.run_log.write();
            run_log.push(log_entry);
            // Keep only last 1000 entries
            if run_log.len() > 1000 {
                let drain_count = run_log.len() - 1000;
                run_log.drain(0..drain_count);
            }
        }

        self.emit_event(CronEvent {
            job_id,
            action: CronEventAction::Finished,
            next_run_at_ms: next_run,
            details: Some(serde_json::json!({
                "status": "ok",
                "durationMs": duration_ms
            })),
        });

        Ok(CronRunResult {
            ok: true,
            ran: true,
            reason: None,
        })
    }

    /// Get run history for a job (or all jobs if no id provided).
    pub fn runs(&self, job_id: Option<&str>, limit: Option<usize>) -> Vec<CronRunLogEntry> {
        let limit = limit.unwrap_or(200).min(5000);
        let run_log = self.run_log.read();

        let entries: Vec<CronRunLogEntry> = if let Some(id) = job_id {
            run_log.iter().filter(|e| e.job_id == id).cloned().collect()
        } else {
            run_log.clone()
        };

        // Return most recent entries
        if entries.len() > limit {
            entries[entries.len() - limit..].to_vec()
        } else {
            entries
        }
    }

    /// Get a specific job by ID.
    pub fn get(&self, id: &str) -> Option<CronJob> {
        let jobs = self.jobs.read();
        jobs.iter().find(|j| j.id == id).cloned()
    }

    fn emit_event(&self, event: CronEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }
}

/// Status of the cron scheduler.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CronStatus {
    pub enabled: bool,
    #[serde(rename = "storePath")]
    pub store_path: String,
    pub jobs: usize,
    #[serde(rename = "nextRunAtMs", skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<u64>,
}

/// Result of removing a job.
#[derive(Debug, Clone, Serialize)]
pub struct CronRemoveResult {
    pub ok: bool,
    pub removed: bool,
}

/// Mode for running a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CronRunMode {
    /// Only run if the job is due.
    Due,
    /// Force run regardless of schedule.
    Force,
}

impl CronRunMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "due" => Some(Self::Due),
            "force" => Some(Self::Force),
            _ => None,
        }
    }
}

/// Reason why a job did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CronRunReason {
    NotDue,
}

/// Result of running a job.
#[derive(Debug, Clone, Serialize)]
pub struct CronRunResult {
    pub ok: bool,
    pub ran: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<CronRunReason>,
}

/// Errors that can occur in the cron scheduler.
#[derive(Debug, thiserror::Error)]
pub enum CronError {
    #[error("job not found: {0}")]
    JobNotFound(String),
    #[error("store error: {0}")]
    StoreError(String),
    #[error("job limit exceeded (max {0})")]
    LimitExceeded(usize),
}

/// Create a shared cron scheduler.
pub fn create_scheduler(store_path: PathBuf, enabled: bool) -> Arc<CronScheduler> {
    Arc::new(CronScheduler::new(store_path, enabled))
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_scheduler_new() {
        let scheduler = CronScheduler::in_memory();
        assert!(scheduler.is_enabled());
    }

    #[test]
    fn test_cron_scheduler_status() {
        let scheduler = CronScheduler::in_memory();
        let status = scheduler.status();
        assert!(status.enabled);
        assert_eq!(status.jobs, 0);
        assert!(status.next_run_at_ms.is_none());
    }

    #[test]
    fn test_cron_scheduler_add_job() {
        let scheduler = CronScheduler::in_memory();

        let input = CronJobCreate {
            name: "Test Job".to_string(),
            agent_id: None,
            description: Some("A test job".to_string()),
            enabled: true,
            delete_after_run: None,
            schedule: CronSchedule::Every {
                every_ms: 60_000,
                anchor_ms: None,
            },
            session_target: CronSessionTarget::Main,
            wake_mode: CronWakeMode::Now,
            payload: CronPayload::SystemEvent {
                text: "Hello from cron!".to_string(),
            },
            isolation: None,
        };

        let job = scheduler.add(input).unwrap();
        assert!(!job.id.is_empty());
        assert_eq!(job.name, "Test Job");
        assert!(job.enabled);
        assert!(job.state.next_run_at_ms.is_some());

        let status = scheduler.status();
        assert_eq!(status.jobs, 1);
    }

    #[test]
    fn test_cron_scheduler_list_jobs() {
        let scheduler = CronScheduler::in_memory();

        // Add enabled job
        scheduler
            .add(CronJobCreate {
                name: "Enabled Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 60_000,
                    anchor_ms: None,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Add disabled job
        scheduler
            .add(CronJobCreate {
                name: "Disabled Job".to_string(),
                agent_id: None,
                description: None,
                enabled: false,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 60_000,
                    anchor_ms: None,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // List only enabled
        let enabled_jobs = scheduler.list(false);
        assert_eq!(enabled_jobs.len(), 1);
        assert_eq!(enabled_jobs[0].name, "Enabled Job");

        // List all
        let all_jobs = scheduler.list(true);
        assert_eq!(all_jobs.len(), 2);
    }

    #[test]
    fn test_cron_scheduler_update_job() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Original Name".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 60_000,
                    anchor_ms: None,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        let updated = scheduler
            .update(
                &job.id,
                CronJobPatch {
                    name: Some("Updated Name".to_string()),
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(updated.name, "Updated Name");
        assert!(!updated.enabled);
        assert!(updated.state.next_run_at_ms.is_none());
    }

    #[test]
    fn test_cron_scheduler_remove_job() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "To Remove".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 60_000,
                    anchor_ms: None,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        assert_eq!(scheduler.list(true).len(), 1);

        let result = scheduler.remove(&job.id);
        assert!(result.ok);
        assert!(result.removed);

        assert_eq!(scheduler.list(true).len(), 0);

        // Removing non-existent job
        let result = scheduler.remove("non-existent");
        assert!(result.ok);
        assert!(!result.removed);
    }

    #[test]
    fn test_cron_scheduler_run_job() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Runnable Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::At { at_ms: 0 }, // Already due
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Force run
        let result = scheduler.run(&job.id, Some(CronRunMode::Force)).unwrap();
        assert!(result.ok);
        assert!(result.ran);

        // Check run was logged
        let runs = scheduler.runs(Some(&job.id), None);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].job_id, job.id);
    }

    #[test]
    fn test_cron_scheduler_run_not_due() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Future Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::At {
                    at_ms: now_ms() + 1_000_000,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Due mode should not run
        let result = scheduler.run(&job.id, Some(CronRunMode::Due)).unwrap();
        assert!(result.ok);
        assert!(!result.ran);
        assert_eq!(result.reason, Some(CronRunReason::NotDue));
    }

    #[test]
    fn test_cron_scheduler_get_job() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Get Test".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 60_000,
                    anchor_ms: None,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        let fetched = scheduler.get(&job.id);
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "Get Test");

        let not_found = scheduler.get("non-existent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_cron_scheduler_job_limit() {
        let scheduler = CronScheduler::in_memory();

        // Fill to the limit
        for i in 0..CronScheduler::MAX_JOBS {
            scheduler
                .add(CronJobCreate {
                    name: format!("Job {}", i),
                    agent_id: None,
                    description: None,
                    enabled: false,
                    delete_after_run: None,
                    schedule: CronSchedule::At { at_ms: 0 },
                    session_target: CronSessionTarget::Main,
                    wake_mode: CronWakeMode::Now,
                    payload: CronPayload::SystemEvent {
                        text: "t".to_string(),
                    },
                    isolation: None,
                })
                .unwrap();
        }

        // One more should fail
        let result = scheduler.add(CronJobCreate {
            name: "Over Limit".to_string(),
            agent_id: None,
            description: None,
            enabled: false,
            delete_after_run: None,
            schedule: CronSchedule::At { at_ms: 0 },
            session_target: CronSessionTarget::Main,
            wake_mode: CronWakeMode::Now,
            payload: CronPayload::SystemEvent {
                text: "t".to_string(),
            },
            isolation: None,
        });
        assert!(matches!(result, Err(CronError::LimitExceeded(500))));

        // Removing one and adding should succeed
        let jobs = scheduler.list(true);
        scheduler.remove(&jobs[0].id);
        assert!(scheduler
            .add(CronJobCreate {
                name: "After Remove".to_string(),
                agent_id: None,
                description: None,
                enabled: false,
                delete_after_run: None,
                schedule: CronSchedule::At { at_ms: 0 },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "t".to_string(),
                },
                isolation: None,
            })
            .is_ok());
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

    #[test]
    fn test_cron_run_mode_from_str() {
        assert_eq!(CronRunMode::from_str("due"), Some(CronRunMode::Due));
        assert_eq!(CronRunMode::from_str("force"), Some(CronRunMode::Force));
        assert_eq!(CronRunMode::from_str("invalid"), None);
    }

    #[test]
    fn test_compute_next_run_every_zero_returns_none() {
        // Defensive guard: everyMs=0 should return None instead of panicking with divide-by-zero
        let schedule = CronSchedule::Every {
            every_ms: 0,
            anchor_ms: None,
        };
        assert_eq!(compute_next_run(&schedule, 1000), None);
    }
}
