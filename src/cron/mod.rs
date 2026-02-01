//! Cron scheduler system.
//!
//! This module provides a cron-like job scheduling system that supports:
//! - One-shot jobs (run at specific time)
//! - Interval jobs (run every N milliseconds)
//! - Cron expression jobs (run on cron schedule with optional timezone)
//!
//! Jobs can execute either in the main session or in isolated sessions,
//! and can deliver messages to various channels.

pub mod executor;
pub mod tick;

use chrono::{Datelike, Offset, TimeZone, Timelike, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// The cron scheduler service.
///
/// When `persist_path` is `Some`, jobs are flushed to disk on every mutation
/// and reloaded on startup. When `None` (the `in_memory()` constructor),
/// behaviour is identical to the original in-memory-only scheduler.
#[derive(Debug)]
pub struct CronScheduler {
    enabled: bool,
    pub(crate) jobs: RwLock<Vec<CronJob>>,
    run_log: RwLock<Vec<CronRunLogEntry>>,
    event_tx: Option<mpsc::UnboundedSender<CronEvent>>,
    persist_path: Option<PathBuf>,
    /// Whether we have already ensured the persist directory exists.
    dir_ensured: AtomicBool,
}

impl CronScheduler {
    /// Create a new cron scheduler.
    ///
    /// When `persist_path` is `Some`, jobs are flushed to disk on every
    /// mutation. Call [`load()`](Self::load) after construction to restore
    /// previously persisted jobs.
    pub fn new(enabled: bool, persist_path: Option<PathBuf>) -> Self {
        Self {
            enabled,
            jobs: RwLock::new(Vec::new()),
            run_log: RwLock::new(Vec::new()),
            event_tx: None,
            persist_path,
            dir_ensured: AtomicBool::new(false),
        }
    }

    /// Create a new in-memory cron scheduler (for testing).
    pub fn in_memory() -> Self {
        Self {
            enabled: true,
            jobs: RwLock::new(Vec::new()),
            run_log: RwLock::new(Vec::new()),
            event_tx: None,
            persist_path: None,
            dir_ensured: AtomicBool::new(false),
        }
    }

    /// Set the event channel for emitting cron events.
    pub fn with_event_channel(mut self, tx: mpsc::UnboundedSender<CronEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// Load persisted jobs from disk.
    ///
    /// If `persist_path` is `None` or the file does not exist, this is a no-op.
    /// Stale runtime state (`running_at_ms`) is cleared and `next_run_at_ms` is
    /// recomputed for enabled jobs. Errors are logged but never propagated —
    /// the scheduler starts empty on failure.
    pub fn load(&self) {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return,
        };

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "failed to read cron jobs file");
                return;
            }
        };

        let mut loaded: Vec<CronJob> = match serde_json::from_slice(&data) {
            Ok(jobs) => jobs,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "failed to parse cron jobs file");
                return;
            }
        };

        let now = now_ms();
        for job in &mut loaded {
            // Clear stale runtime state — the process just started, nothing is running.
            job.state.running_at_ms = None;
            // Recompute next run time for enabled jobs.
            if job.enabled {
                job.state.next_run_at_ms = compute_next_run(&job.schedule, now);
            }
        }

        let count = loaded.len();
        *self.jobs.write() = loaded;
        tracing::info!(count, path = %path.display(), "loaded cron jobs from disk");
    }

    /// Flush the current jobs list to disk via atomic write.
    ///
    /// No-op when `persist_path` is `None`. Errors are logged but never
    /// propagated — persistence is best-effort.
    ///
    /// Note: this performs synchronous `sync_data` (fsync) on every call.
    /// For high-frequency mutation patterns a debounced/batched flush would
    /// reduce I/O overhead, but for the expected cron-job cardinality (≤500
    /// jobs, mutations at human timescales) this is acceptable.
    fn flush_to_disk(&self) {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return,
        };

        // Ensure parent directory exists (once per scheduler lifetime).
        if !self.dir_ensured.load(Ordering::Relaxed) {
            if let Some(parent) = path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    tracing::error!(path = %parent.display(), error = %e, "failed to create cron dir");
                    return;
                }
            }
            self.dir_ensured.store(true, Ordering::Relaxed);
        }

        // Construct tmp path by appending ".tmp" so it is stable regardless
        // of how many dots the filename contains.
        let tmp_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };

        // Serialize while holding a read lock.
        let mut data = {
            let jobs = self.jobs.read();
            match serde_json::to_vec_pretty(&*jobs) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "failed to serialize cron jobs");
                    return;
                }
            }
        };
        data.push(b'\n');

        // Write to tmp file, sync data, rename.
        let write_result = (|| -> std::io::Result<()> {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&data)?;
            file.sync_data()?;
            fs::rename(&tmp_path, path)?;
            Ok(())
        })();

        if let Err(e) = write_result {
            tracing::error!(path = %path.display(), error = %e, "failed to flush cron jobs to disk");
            // Best-effort cleanup of tmp file.
            let _ = fs::remove_file(&tmp_path);
        }
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

    fn last_used_at(job: &CronJob) -> u64 {
        job.state
            .last_run_at_ms
            .unwrap_or(0)
            .max(job.updated_at_ms)
            .max(job.created_at_ms)
    }

    /// Add a new job.
    pub fn add(&self, input: CronJobCreate) -> Result<CronJob, CronError> {
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

        let mut evicted_job: Option<CronJob> = None;
        {
            let mut jobs = self.jobs.write();
            if jobs.len() >= Self::MAX_JOBS {
                let eviction = jobs
                    .iter()
                    .enumerate()
                    .filter(|(_, job)| job.state.running_at_ms.is_none())
                    .min_by_key(|(_, job)| Self::last_used_at(job))
                    .map(|(idx, _)| idx);
                if let Some(idx) = eviction {
                    evicted_job = Some(jobs.remove(idx));
                } else {
                    return Err(CronError::LimitExceeded(Self::MAX_JOBS));
                }
            }
            jobs.push(job.clone());
        }

        self.flush_to_disk();

        if let Some(evicted) = evicted_job {
            self.emit_event(CronEvent {
                job_id: evicted.id,
                action: CronEventAction::Removed,
                next_run_at_ms: None,
                details: Some(serde_json::json!({
                    "reason": "evicted",
                    "evictedBy": job_id,
                })),
            });
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

        self.flush_to_disk();

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
            self.flush_to_disk();
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
                payload: None,
                job_id: id.to_string(),
            });
        }

        // Mark as running
        job.state.running_at_ms = Some(now);

        // Compute next run time so scheduler won't re-fire
        job.state.next_run_at_ms = compute_next_run(&job.schedule, now);

        // Clone payload before dropping the lock
        let payload = job.payload.clone();
        let next_run_at_ms = job.state.next_run_at_ms;
        let job_id = id.to_string();

        drop(jobs);

        self.flush_to_disk();

        self.emit_event(CronEvent {
            job_id: job_id.clone(),
            action: CronEventAction::Started,
            next_run_at_ms,
            details: None,
        });

        // Actual execution is handled by the caller (cron executor / tick loop).
        // This method returns the payload for async execution.
        Ok(CronRunResult {
            ok: true,
            ran: true,
            reason: None,
            payload: Some(payload),
            job_id,
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

    /// Get IDs of jobs that are due to run now.
    ///
    /// Returns job IDs that are enabled, not currently running, and past their next_run_at_ms.
    pub fn get_due_job_ids(&self) -> Vec<String> {
        let now = now_ms();
        let jobs = self.jobs.read();
        jobs.iter()
            .filter(|j| {
                j.enabled
                    && j.state.running_at_ms.is_none()
                    && j.state.next_run_at_ms.is_some_and(|next| now >= next)
            })
            .map(|j| j.id.clone())
            .collect()
    }

    /// Mark a job run as finished, updating state and recording a log entry.
    ///
    /// Called by the cron executor after payload execution completes.
    pub fn mark_run_finished(
        &self,
        job_id: &str,
        status: CronJobStatus,
        duration_ms: u64,
        error: Option<String>,
    ) -> Result<(), CronError> {
        let now = now_ms();
        let mut jobs = self.jobs.write();
        let job = jobs
            .iter_mut()
            .find(|j| j.id == job_id)
            .ok_or_else(|| CronError::JobNotFound(job_id.to_string()))?;

        job.state.running_at_ms = None;
        job.state.last_run_at_ms = Some(now);
        job.state.last_duration_ms = Some(duration_ms);
        job.state.last_status = Some(status);
        job.state.last_error = error.clone();

        let should_delete = job.delete_after_run == Some(true);
        let next_run = job.state.next_run_at_ms;
        let job_id_owned = job_id.to_string();
        drop(jobs);

        self.flush_to_disk();

        // Record run log
        let log_entry = CronRunLogEntry {
            ts: now,
            job_id: job_id_owned.clone(),
            action: "finished".to_string(),
            status: Some(status),
            error,
            summary: None,
            run_at_ms: Some(now),
            duration_ms: Some(duration_ms),
            next_run_at_ms: next_run,
        };

        {
            let mut run_log = self.run_log.write();
            run_log.push(log_entry);
            if run_log.len() > 1000 {
                let drain_count = run_log.len() - 1000;
                run_log.drain(0..drain_count);
            }
        }

        self.emit_event(CronEvent {
            job_id: job_id_owned.clone(),
            action: CronEventAction::Finished,
            next_run_at_ms: next_run,
            details: Some(serde_json::json!({
                "status": format!("{:?}", status),
                "durationMs": duration_ms
            })),
        });

        if should_delete {
            self.remove(&job_id_owned);
        }

        Ok(())
    }

    fn emit_event(&self, event: CronEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }

    /// Test helper: mutate a job's runtime state and flush to disk.
    ///
    /// Avoids tests reaching into `self.jobs.write()` directly, which
    /// couples them to the internal lock type.
    #[cfg(test)]
    fn set_job_running_for_test(&self, job_id: &str, running_at_ms: Option<u64>) {
        let mut jobs = self.jobs.write();
        if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
            job.state.running_at_ms = running_at_ms;
        }
        drop(jobs);
        self.flush_to_disk();
    }
}

/// Status of the cron scheduler.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CronStatus {
    pub enabled: bool,
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
    pub fn parse_mode(s: &str) -> Option<Self> {
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
    /// The job payload (present when the job ran)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<CronPayload>,
    /// The job ID
    #[serde(rename = "jobId")]
    pub job_id: String,
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

/// A parsed cron expression (5-field: minute hour day-of-month month day-of-week).
///
/// Each field is stored as a set of valid values. A datetime matches when all
/// five fields match the corresponding component.
#[derive(Debug, Clone)]
pub struct CronExpr {
    /// Valid minutes (0-59).
    pub minutes: BTreeSet<u32>,
    /// Valid hours (0-23).
    pub hours: BTreeSet<u32>,
    /// Valid days of month (1-31).
    pub days_of_month: BTreeSet<u32>,
    /// Valid months (1-12).
    pub months: BTreeSet<u32>,
    /// Valid days of week (0-6, where 0=Sunday).
    pub days_of_week: BTreeSet<u32>,
}

/// Errors from parsing a cron expression.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CronParseError {
    #[error("expected 5 fields, got {0}")]
    WrongFieldCount(usize),
    #[error("invalid field '{field}': {reason}")]
    InvalidField { field: String, reason: String },
}

impl CronExpr {
    /// Parse a standard 5-field cron expression.
    ///
    /// Format: `minute hour day-of-month month day-of-week`
    ///
    /// Each field supports: `*`, a number, a range (`1-5`), a list (`1,3,5`),
    /// and steps (`*/5`, `1-10/2`).
    pub fn parse(expr: &str) -> Result<Self, CronParseError> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(CronParseError::WrongFieldCount(fields.len()));
        }

        let minutes = Self::parse_field(fields[0], 0, 59, "minute")?;
        let hours = Self::parse_field(fields[1], 0, 23, "hour")?;
        let days_of_month = Self::parse_field(fields[2], 1, 31, "day-of-month")?;
        let months = Self::parse_field(fields[3], 1, 12, "month")?;
        let days_of_week = Self::parse_dow_field(fields[4])?;

        Ok(Self {
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
        })
    }

    /// Parse a single cron field into a set of valid values.
    ///
    /// The field can contain comma-separated items, where each item is one of:
    /// - `*`           -> all values from `min` to `max`
    /// - `*/step`      -> values from `min` to `max` stepping by `step`
    /// - `N`           -> single value
    /// - `N-M`         -> range from `N` to `M` inclusive
    /// - `N-M/step`    -> range with step
    fn parse_field(
        field: &str,
        min: u32,
        max: u32,
        name: &str,
    ) -> Result<BTreeSet<u32>, CronParseError> {
        let mut result = BTreeSet::new();
        for part in field.split(',') {
            let values = Self::parse_field_part(part, min, max, name)?;
            result.extend(values);
        }
        if result.is_empty() {
            return Err(CronParseError::InvalidField {
                field: field.to_string(),
                reason: format!("{name} field produced no valid values"),
            });
        }
        Ok(result)
    }

    /// Parse a single comma-separated item of a cron field.
    fn parse_field_part(
        part: &str,
        min: u32,
        max: u32,
        name: &str,
    ) -> Result<BTreeSet<u32>, CronParseError> {
        let make_err = |reason: String| CronParseError::InvalidField {
            field: part.to_string(),
            reason,
        };

        // Split on '/' first to handle steps
        let (range_part, step) = if let Some((r, s)) = part.split_once('/') {
            let step: u32 = s
                .parse()
                .map_err(|_| make_err(format!("invalid step '{s}' in {name}")))?;
            if step == 0 {
                return Err(make_err(format!("step cannot be 0 in {name}")));
            }
            (r, Some(step))
        } else {
            (part, None)
        };

        // Determine the range of values
        let (range_min, range_max) = if range_part == "*" {
            (min, max)
        } else if let Some((lo, hi)) = range_part.split_once('-') {
            let lo: u32 = lo
                .parse()
                .map_err(|_| make_err(format!("invalid range start '{lo}' in {name}")))?;
            let hi: u32 = hi
                .parse()
                .map_err(|_| make_err(format!("invalid range end '{hi}' in {name}")))?;
            if lo < min || hi > max {
                return Err(make_err(format!(
                    "range {lo}-{hi} out of bounds ({min}-{max}) for {name}"
                )));
            }
            if lo > hi {
                return Err(make_err(format!("range start {lo} > end {hi} in {name}")));
            }
            (lo, hi)
        } else {
            // Single number
            let val: u32 = range_part
                .parse()
                .map_err(|_| make_err(format!("invalid value '{range_part}' in {name}")))?;
            if val < min || val > max {
                return Err(make_err(format!(
                    "value {val} out of bounds ({min}-{max}) for {name}"
                )));
            }
            if let Some(s) = step {
                // e.g. "5/2" means starting at 5, stepping by 2 up to max
                let mut set = BTreeSet::new();
                let mut v = val;
                while v <= max {
                    set.insert(v);
                    v += s;
                }
                return Ok(set);
            }
            return Ok(BTreeSet::from([val]));
        };

        // Build the set from range with optional step
        let step = step.unwrap_or(1);
        let mut set = BTreeSet::new();
        let mut v = range_min;
        while v <= range_max {
            set.insert(v);
            v += step;
        }
        Ok(set)
    }

    /// Parse the day-of-week field, handling 7 as an alias for Sunday (0).
    fn parse_dow_field(field: &str) -> Result<BTreeSet<u32>, CronParseError> {
        // Day-of-week: 0-7 where 0 and 7 both mean Sunday.
        // We parse with range 0-7, then normalize 7 -> 0.
        let mut result = BTreeSet::new();
        for part in field.split(',') {
            let values = Self::parse_field_part(part, 0, 7, "day-of-week")?;
            result.extend(values);
        }
        // Normalize: 7 -> 0 (Sunday)
        if result.remove(&7) {
            result.insert(0);
        }
        if result.is_empty() {
            return Err(CronParseError::InvalidField {
                field: field.to_string(),
                reason: "day-of-week field produced no valid values".to_string(),
            });
        }
        Ok(result)
    }

    /// Check whether raw time components match this cron expression.
    fn matches_components(&self, minute: u32, hour: u32, day: u32, month: u32, dow: u32) -> bool {
        self.minutes.contains(&minute)
            && self.hours.contains(&hour)
            && self.days_of_month.contains(&day)
            && self.months.contains(&month)
            && self.days_of_week.contains(&dow)
    }

    /// Check if a `chrono::DateTime<Utc>` matches this cron expression.
    pub fn matches(&self, dt: &chrono::DateTime<Utc>) -> bool {
        let minute = dt.minute();
        let hour = dt.hour();
        let day = dt.day();
        let month = dt.month();
        // chrono: Mon=0 .. Sun=6 via weekday().num_days_from_monday()
        // cron: Sun=0, Mon=1 .. Sat=6 via weekday().num_days_from_sunday()
        let dow = dt.weekday().num_days_from_sunday();

        self.matches_components(minute, hour, day, month, dow)
    }

    /// Find the next minute (as UTC `DateTime`) after `after` that matches this expression.
    ///
    /// Searches up to ~4 years (2,100,000 minutes) to account for leap years and
    /// edge cases. Returns `None` if no match is found (e.g., Feb 31).
    pub fn next_after(&self, after: &chrono::DateTime<Utc>) -> Option<chrono::DateTime<Utc>> {
        use chrono::Duration as CDuration;

        // Start from the next whole minute after `after`
        let mut candidate = *after + CDuration::seconds(60 - after.second() as i64)
            - CDuration::nanoseconds(after.nanosecond() as i64);
        // If `after` was already at a whole minute boundary, we already advanced by 60s,
        // which is what we want (next minute after `after`, not `after` itself).
        // But if after had sub-minute components, the above math may still land on the same
        // minute. Let's normalize to ensure we're at seconds=0, nanos=0 of the next minute.
        candidate = candidate
            .with_second(0)
            .unwrap_or(candidate)
            .with_nanosecond(0)
            .unwrap_or(candidate);

        // If we're still at or before `after`, push forward one more minute
        if candidate <= *after {
            candidate += CDuration::minutes(1);
        }

        // Search up to ~4 years of minutes
        let max_iterations = 2_100_000u32;
        for _ in 0..max_iterations {
            if self.matches(&candidate) {
                return Some(candidate);
            }
            candidate += CDuration::minutes(1);
        }
        None
    }
}

/// Find the next UTC minute after `after` whose local-time representation in
/// `tz` matches `expr`.
///
/// Uses brute-force minute iteration (same budget as `CronExpr::next_after`)
/// but converts each UTC candidate to the target timezone before matching.
///
/// **Fall-back deduplication:** during a DST fall-back two consecutive UTC
/// instants map to the same local clock reading. We fire only on the *first*
/// occurrence by checking whether the UTC offset decreased compared to one
/// hour earlier at the same local time.
fn next_after_in_tz(
    expr: &CronExpr,
    after: &chrono::DateTime<Utc>,
    tz: chrono_tz::Tz,
) -> Option<chrono::DateTime<Utc>> {
    use chrono::Duration as CDuration;

    // Start from the next whole UTC minute after `after`.
    let mut candidate = *after + CDuration::seconds(60 - after.second() as i64)
        - CDuration::nanoseconds(after.nanosecond() as i64);
    candidate = candidate
        .with_second(0)
        .unwrap_or(candidate)
        .with_nanosecond(0)
        .unwrap_or(candidate);
    if candidate <= *after {
        candidate += CDuration::minutes(1);
    }

    let max_iterations = 2_100_000u32;
    for _ in 0..max_iterations {
        let local = candidate.with_timezone(&tz);
        let minute = local.minute();
        let hour = local.hour();
        let day = local.day();
        let month = local.month();
        let dow = local.weekday().num_days_from_sunday();

        if expr.matches_components(minute, hour, day, month, dow) {
            // Fall-back dedup: if offset decreased vs one hour ago AND the
            // local clock reading was the same, this is the second occurrence
            // of an ambiguous wall-clock time — skip it.
            let one_hour_ago = candidate - CDuration::hours(1);
            let local_ago = one_hour_ago.with_timezone(&tz);
            let offset_now = local.offset().fix().local_minus_utc();
            let offset_ago = local_ago.offset().fix().local_minus_utc();
            if offset_now < offset_ago && local_ago.hour() == hour && local_ago.minute() == minute {
                candidate += CDuration::minutes(1);
                continue;
            }
            return Some(candidate);
        }
        candidate += CDuration::minutes(1);
    }
    None
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
        CronSchedule::Cron { expr, tz } => {
            let parsed = match CronExpr::parse(expr) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(expr = %expr, error = %e, "invalid cron expression");
                    return None;
                }
            };
            let now_dt = Utc.timestamp_millis_opt(now as i64).single()?;

            // Determine timezone: None or "UTC" → fast path, otherwise parse IANA tz.
            let timezone: Option<chrono_tz::Tz> = match tz.as_deref() {
                None => None,
                Some(s) if s.eq_ignore_ascii_case("UTC") => None,
                Some(tz_str) => match tz_str.parse::<chrono_tz::Tz>() {
                    Ok(t) => Some(t),
                    Err(_) => {
                        tracing::error!(tz = %tz_str, "invalid IANA timezone for cron expression");
                        return None;
                    }
                },
            };

            let next_dt = match timezone {
                None => parsed.next_after(&now_dt)?,
                Some(tz_val) => next_after_in_tz(&parsed, &now_dt, tz_val)?,
            };
            Some(next_dt.timestamp_millis() as u64)
        }
    }
}

pub(crate) fn now_ms() -> u64 {
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
        assert!(result.payload.is_some());
        assert_eq!(result.job_id, job.id);

        // Run no longer records log entry — that's done by mark_run_finished.
        // Simulate the executor finishing:
        scheduler
            .mark_run_finished(&job.id, CronJobStatus::Ok, 0, None)
            .unwrap();

        // Check run was logged by mark_run_finished
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
        let mut existing_ids = Vec::new();
        for i in 0..CronScheduler::MAX_JOBS {
            let job = scheduler
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
            existing_ids.push(job.id);
        }

        // One more should evict the least recently used job
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
        let new_job = result.unwrap();
        assert_eq!(scheduler.jobs.read().len(), CronScheduler::MAX_JOBS);
        assert!(scheduler.get(&new_job.id).is_some());
        let remaining_ids: std::collections::HashSet<_> =
            scheduler.list(true).into_iter().map(|j| j.id).collect();
        assert!(
            existing_ids.iter().any(|id| !remaining_ids.contains(id)),
            "expected at least one existing job to be evicted"
        );
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
        assert_eq!(CronRunMode::parse_mode("due"), Some(CronRunMode::Due));
        assert_eq!(CronRunMode::parse_mode("force"), Some(CronRunMode::Force));
        assert_eq!(CronRunMode::parse_mode("invalid"), None);
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

    #[test]
    fn test_get_due_job_ids_filters_correctly() {
        let scheduler = CronScheduler::in_memory();

        // Enabled, due, not running → should be included
        // Use Every schedule with anchor in the past so next_run_at_ms is in the past
        let due_job = scheduler
            .add(CronJobCreate {
                name: "Due Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 1_000_000_000, // large interval
                    anchor_ms: Some(1),      // anchor far in past → next_run = anchor + k*every
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "due".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Manually set next_run_at_ms to a past time so it's due
        {
            let mut jobs = scheduler.jobs.write();
            let job = jobs.iter_mut().find(|j| j.id == due_job.id).unwrap();
            job.state.next_run_at_ms = Some(1); // epoch + 1ms, definitely past
        }

        // Disabled → should be excluded
        let _disabled_job = scheduler
            .add(CronJobCreate {
                name: "Disabled Job".to_string(),
                agent_id: None,
                description: None,
                enabled: false,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 60000,
                    anchor_ms: None,
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "disabled".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Not due (future) → should be excluded
        let _future_job = scheduler
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
                    text: "future".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        let due_ids = scheduler.get_due_job_ids();
        assert_eq!(due_ids.len(), 1);
        assert_eq!(due_ids[0], due_job.id);
    }

    #[test]
    fn test_run_returns_payload() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Payload Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::At { at_ms: 0 },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "payload test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        let result = scheduler.run(&job.id, Some(CronRunMode::Force)).unwrap();
        assert!(result.ok);
        assert!(result.ran);
        assert!(result.payload.is_some());

        match result.payload.unwrap() {
            CronPayload::SystemEvent { text } => assert_eq!(text, "payload test"),
            _ => panic!("expected SystemEvent payload"),
        }
    }

    #[test]
    fn test_mark_run_finished_updates_state() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Finish Test".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::At { at_ms: 0 },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Start the run
        let result = scheduler.run(&job.id, Some(CronRunMode::Force)).unwrap();
        assert!(result.ran);

        // Mark as finished
        scheduler
            .mark_run_finished(&job.id, CronJobStatus::Ok, 42, None)
            .unwrap();

        // Verify state was updated
        let updated = scheduler.get(&job.id).unwrap();
        assert!(updated.state.running_at_ms.is_none());
        assert!(updated.state.last_run_at_ms.is_some());
        assert_eq!(updated.state.last_duration_ms, Some(42));
        assert_eq!(updated.state.last_status, Some(CronJobStatus::Ok));
        assert!(updated.state.last_error.is_none());

        // Verify log entry was recorded
        let runs = scheduler.runs(Some(&job.id), None);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].action, "finished");
        assert_eq!(runs[0].duration_ms, Some(42));
    }

    #[test]
    fn test_mark_run_finished_deletes_oneshot() {
        let scheduler = CronScheduler::in_memory();

        let job = scheduler
            .add(CronJobCreate {
                name: "Oneshot Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: Some(true),
                schedule: CronSchedule::At { at_ms: 0 },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "oneshot".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Start and finish the run
        let result = scheduler.run(&job.id, Some(CronRunMode::Force)).unwrap();
        assert!(result.ran);

        scheduler
            .mark_run_finished(&job.id, CronJobStatus::Ok, 10, None)
            .unwrap();

        // Job should have been removed
        assert!(scheduler.get(&job.id).is_none());
    }

    // ---------------------------------------------------------------
    // CronExpr parsing and matching tests
    // ---------------------------------------------------------------

    /// Helper: create a UTC datetime for testing.
    fn utc(year: i32, month: u32, day: u32, hour: u32, min: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
    }

    #[test]
    fn test_cron_expr_star_matches_every_minute() {
        let expr = CronExpr::parse("* * * * *").unwrap();
        // Should match any arbitrary datetime
        assert!(expr.matches(&utc(2025, 6, 15, 14, 30)));
        assert!(expr.matches(&utc(2025, 1, 1, 0, 0)));
        assert!(expr.matches(&utc(2025, 12, 31, 23, 59)));
    }

    #[test]
    fn test_cron_expr_minute_zero() {
        let expr = CronExpr::parse("0 * * * *").unwrap();
        // Matches at minute 0
        assert!(expr.matches(&utc(2025, 6, 15, 14, 0)));
        assert!(expr.matches(&utc(2025, 6, 15, 0, 0)));
        // Does not match at other minutes
        assert!(!expr.matches(&utc(2025, 6, 15, 14, 1)));
        assert!(!expr.matches(&utc(2025, 6, 15, 14, 30)));
        assert!(!expr.matches(&utc(2025, 6, 15, 14, 59)));
    }

    #[test]
    fn test_cron_expr_specific_time() {
        // "30 2 * * *" matches only at 2:30
        let expr = CronExpr::parse("30 2 * * *").unwrap();
        assert!(expr.matches(&utc(2025, 6, 15, 2, 30)));
        assert!(expr.matches(&utc(2025, 1, 1, 2, 30)));
        // Does not match at other times
        assert!(!expr.matches(&utc(2025, 6, 15, 2, 31)));
        assert!(!expr.matches(&utc(2025, 6, 15, 3, 30)));
        assert!(!expr.matches(&utc(2025, 6, 15, 14, 30)));
    }

    #[test]
    fn test_cron_expr_step_every_15_minutes() {
        // "*/15 * * * *" matches at 0, 15, 30, 45
        let expr = CronExpr::parse("*/15 * * * *").unwrap();
        assert!(expr.matches(&utc(2025, 6, 15, 10, 0)));
        assert!(expr.matches(&utc(2025, 6, 15, 10, 15)));
        assert!(expr.matches(&utc(2025, 6, 15, 10, 30)));
        assert!(expr.matches(&utc(2025, 6, 15, 10, 45)));
        // Does not match at other minutes
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 1)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 14)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 16)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 59)));

        // Verify the exact minute set
        let expected: BTreeSet<u32> = [0, 15, 30, 45].into();
        assert_eq!(expr.minutes, expected);
    }

    #[test]
    fn test_cron_expr_weekday_business_hours() {
        // "0 9-17 * * 1-5" matches hourly 9am-5pm on weekdays (Mon-Fri)
        let expr = CronExpr::parse("0 9-17 * * 1-5").unwrap();

        // 2025-06-16 is a Monday
        assert!(expr.matches(&utc(2025, 6, 16, 9, 0)));
        assert!(expr.matches(&utc(2025, 6, 16, 12, 0)));
        assert!(expr.matches(&utc(2025, 6, 16, 17, 0)));
        // 2025-06-20 is a Friday
        assert!(expr.matches(&utc(2025, 6, 20, 9, 0)));

        // Should NOT match on Saturday (2025-06-21)
        assert!(!expr.matches(&utc(2025, 6, 21, 9, 0)));
        // Should NOT match on Sunday (2025-06-22)
        assert!(!expr.matches(&utc(2025, 6, 22, 9, 0)));
        // Should NOT match at 8am on Monday
        assert!(!expr.matches(&utc(2025, 6, 16, 8, 0)));
        // Should NOT match at 18:00 on Monday
        assert!(!expr.matches(&utc(2025, 6, 16, 18, 0)));
        // Should NOT match at minute != 0
        assert!(!expr.matches(&utc(2025, 6, 16, 9, 1)));
    }

    #[test]
    fn test_cron_expr_first_of_month_midnight() {
        // "0 0 1 * *" matches midnight on the 1st of every month
        let expr = CronExpr::parse("0 0 1 * *").unwrap();
        assert!(expr.matches(&utc(2025, 1, 1, 0, 0)));
        assert!(expr.matches(&utc(2025, 6, 1, 0, 0)));
        assert!(expr.matches(&utc(2025, 12, 1, 0, 0)));
        // Does not match on other days
        assert!(!expr.matches(&utc(2025, 1, 2, 0, 0)));
        assert!(!expr.matches(&utc(2025, 1, 15, 0, 0)));
        // Does not match at non-midnight
        assert!(!expr.matches(&utc(2025, 1, 1, 1, 0)));
        assert!(!expr.matches(&utc(2025, 1, 1, 0, 1)));
    }

    #[test]
    fn test_cron_expr_sundays_midnight() {
        // "0 0 * * 0" matches midnight on Sundays
        let expr = CronExpr::parse("0 0 * * 0").unwrap();
        // 2025-06-22 is a Sunday
        assert!(expr.matches(&utc(2025, 6, 22, 0, 0)));
        // 2025-06-15 is also a Sunday
        assert!(expr.matches(&utc(2025, 6, 15, 0, 0)));
        // Monday should not match
        assert!(!expr.matches(&utc(2025, 6, 16, 0, 0)));
        // Sunday but not midnight should not match
        assert!(!expr.matches(&utc(2025, 6, 22, 12, 0)));
    }

    #[test]
    fn test_cron_expr_dow_7_is_sunday() {
        // "0 0 * * 7" should also match Sunday (7 is alias for 0)
        let expr = CronExpr::parse("0 0 * * 7").unwrap();
        // 2025-06-22 is a Sunday
        assert!(expr.matches(&utc(2025, 6, 22, 0, 0)));
        // Monday should not match
        assert!(!expr.matches(&utc(2025, 6, 16, 0, 0)));
    }

    #[test]
    fn test_cron_expr_invalid_expressions() {
        // Too few fields
        assert!(CronExpr::parse("* * *").is_err());
        assert!(matches!(
            CronExpr::parse("* * *"),
            Err(CronParseError::WrongFieldCount(3))
        ));

        // Too many fields
        assert!(CronExpr::parse("* * * * * *").is_err());
        assert!(matches!(
            CronExpr::parse("* * * * * *"),
            Err(CronParseError::WrongFieldCount(6))
        ));

        // Empty string
        assert!(CronExpr::parse("").is_err());

        // Invalid values
        assert!(CronExpr::parse("60 * * * *").is_err()); // minute > 59
        assert!(CronExpr::parse("* 24 * * *").is_err()); // hour > 23
        assert!(CronExpr::parse("* * 0 * *").is_err()); // day-of-month < 1
        assert!(CronExpr::parse("* * 32 * *").is_err()); // day-of-month > 31
        assert!(CronExpr::parse("* * * 0 *").is_err()); // month < 1
        assert!(CronExpr::parse("* * * 13 *").is_err()); // month > 12
        assert!(CronExpr::parse("* * * * 8").is_err()); // day-of-week > 7

        // Invalid syntax
        assert!(CronExpr::parse("abc * * * *").is_err());
        assert!(CronExpr::parse("*/0 * * * *").is_err()); // step of 0
        assert!(CronExpr::parse("5-2 * * * *").is_err()); // range start > end
    }

    #[test]
    fn test_cron_expr_feb_31_never_matches() {
        // "0 0 31 2 *" — February 31 never exists
        let expr = CronExpr::parse("0 0 31 2 *").unwrap();
        // No February date should match since Feb never has 31 days
        for day in 1..=28 {
            assert!(!expr.matches(&utc(2025, 2, day, 0, 0)));
        }
        // Even in leap year, Feb 29 doesn't match because we need day 31
        assert!(!expr.matches(&utc(2024, 2, 29, 0, 0)));
    }

    #[test]
    fn test_cron_expr_list_values() {
        // "0,30 * * * *" matches at minute 0 and 30
        let expr = CronExpr::parse("0,30 * * * *").unwrap();
        assert!(expr.matches(&utc(2025, 6, 15, 10, 0)));
        assert!(expr.matches(&utc(2025, 6, 15, 10, 30)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 15)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 1)));
    }

    #[test]
    fn test_cron_expr_range_with_step() {
        // "1-10/2 * * * *" matches at 1,3,5,7,9
        let expr = CronExpr::parse("1-10/2 * * * *").unwrap();
        let expected: BTreeSet<u32> = [1, 3, 5, 7, 9].into();
        assert_eq!(expr.minutes, expected);
        assert!(expr.matches(&utc(2025, 6, 15, 10, 1)));
        assert!(expr.matches(&utc(2025, 6, 15, 10, 3)));
        assert!(expr.matches(&utc(2025, 6, 15, 10, 9)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 2)));
        assert!(!expr.matches(&utc(2025, 6, 15, 10, 10)));
    }

    #[test]
    fn test_cron_expr_next_after_every_minute() {
        let expr = CronExpr::parse("* * * * *").unwrap();
        let now = utc(2025, 6, 15, 10, 30);
        let next = expr.next_after(&now).unwrap();
        assert_eq!(next, utc(2025, 6, 15, 10, 31));
    }

    #[test]
    fn test_cron_expr_next_after_specific_time() {
        // "30 2 * * *" — next occurrence after 2025-06-15 02:30 should be 2025-06-16 02:30
        let expr = CronExpr::parse("30 2 * * *").unwrap();
        let now = utc(2025, 6, 15, 2, 30);
        let next = expr.next_after(&now).unwrap();
        assert_eq!(next, utc(2025, 6, 16, 2, 30));
    }

    #[test]
    fn test_cron_expr_next_after_step() {
        // "*/15 * * * *" — next after 10:02 should be 10:15
        let expr = CronExpr::parse("*/15 * * * *").unwrap();
        let now = utc(2025, 6, 15, 10, 2);
        let next = expr.next_after(&now).unwrap();
        assert_eq!(next, utc(2025, 6, 15, 10, 15));
    }

    #[test]
    fn test_cron_expr_next_after_wraps_hour() {
        // "0 * * * *" — next after 10:30 should be 11:00
        let expr = CronExpr::parse("0 * * * *").unwrap();
        let now = utc(2025, 6, 15, 10, 30);
        let next = expr.next_after(&now).unwrap();
        assert_eq!(next, utc(2025, 6, 15, 11, 0));
    }

    #[test]
    fn test_cron_expr_next_after_wraps_day() {
        // "0 0 * * *" — next after 2025-06-15 23:30 should be 2025-06-16 00:00
        let expr = CronExpr::parse("0 0 * * *").unwrap();
        let now = utc(2025, 6, 15, 23, 30);
        let next = expr.next_after(&now).unwrap();
        assert_eq!(next, utc(2025, 6, 16, 0, 0));
    }

    #[test]
    fn test_cron_expr_feb_31_next_after_returns_none() {
        // "0 0 31 2 *" — Feb 31 never exists, next_after should return None
        let expr = CronExpr::parse("0 0 31 2 *").unwrap();
        let now = utc(2025, 1, 1, 0, 0);
        assert!(expr.next_after(&now).is_none());
    }

    #[test]
    fn test_compute_next_run_cron_schedule() {
        // Ensure compute_next_run works with a real cron expression
        let now_dt = utc(2025, 6, 15, 10, 0);
        let now = now_dt.timestamp_millis() as u64;

        let schedule = CronSchedule::Cron {
            expr: "30 10 * * *".to_string(),
            tz: None,
        };
        let next = compute_next_run(&schedule, now).unwrap();
        let expected = utc(2025, 6, 15, 10, 30).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_compute_next_run_cron_invalid_expr() {
        // Invalid cron expression should return None
        let schedule = CronSchedule::Cron {
            expr: "invalid".to_string(),
            tz: None,
        };
        assert_eq!(compute_next_run(&schedule, 1_000_000), None);
    }

    #[test]
    fn test_cron_expr_complex_list_and_range() {
        // "0,15,30,45 9-17 * 1,6,12 1-5"
        // Every 15 min during business hours, in Jan/Jun/Dec, on weekdays
        let expr = CronExpr::parse("0,15,30,45 9-17 * 1,6,12 1-5").unwrap();
        // 2025-06-16 is Monday in June
        assert!(expr.matches(&utc(2025, 6, 16, 9, 0)));
        assert!(expr.matches(&utc(2025, 6, 16, 12, 15)));
        assert!(expr.matches(&utc(2025, 6, 16, 17, 45)));
        // July should not match (month=7)
        assert!(!expr.matches(&utc(2025, 7, 14, 9, 0)));
        // Saturday should not match
        assert!(!expr.matches(&utc(2025, 6, 21, 9, 0)));
    }

    #[test]
    fn test_cron_expr_single_value_with_step() {
        // "5/10 * * * *" means starting at 5, every 10: 5,15,25,35,45,55
        let expr = CronExpr::parse("5/10 * * * *").unwrap();
        let expected: BTreeSet<u32> = [5, 15, 25, 35, 45, 55].into();
        assert_eq!(expr.minutes, expected);
    }

    #[test]
    fn test_cron_expr_all_stars_fields() {
        let expr = CronExpr::parse("* * * * *").unwrap();
        assert_eq!(expr.minutes.len(), 60); // 0-59
        assert_eq!(expr.hours.len(), 24); // 0-23
        assert_eq!(expr.days_of_month.len(), 31); // 1-31
        assert_eq!(expr.months.len(), 12); // 1-12
        assert_eq!(expr.days_of_week.len(), 7); // 0-6
    }

    #[test]
    fn test_cron_job_limit_enforced_under_concurrent_access() {
        use std::sync::Arc;

        let scheduler = Arc::new(CronScheduler::in_memory());

        // Pre-fill to MAX_JOBS - 1 so there is exactly one slot remaining
        for i in 0..(CronScheduler::MAX_JOBS - 1) {
            scheduler
                .add(CronJobCreate {
                    name: format!("Prefill {i}"),
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

        // Spawn multiple threads that all try to grab the last slot
        let num_threads = 10;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));
        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let sched = Arc::clone(&scheduler);
                let bar = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    bar.wait(); // synchronize start
                    sched.add(CronJobCreate {
                        name: format!("Concurrent {i}"),
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
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        // All concurrent adds should succeed via eviction.
        assert_eq!(successes, num_threads);
        assert_eq!(failures, 0);

        // Total jobs must never exceed MAX_JOBS
        let total = scheduler.jobs.read().len();
        assert_eq!(total, CronScheduler::MAX_JOBS);
    }

    // ---------------------------------------------------------------
    // Persistence tests
    // ---------------------------------------------------------------

    /// Helper: create a simple CronJobCreate for persistence tests.
    fn test_job_create(name: &str) -> CronJobCreate {
        CronJobCreate {
            name: name.to_string(),
            agent_id: None,
            description: Some(format!("desc for {name}")),
            enabled: true,
            delete_after_run: None,
            schedule: CronSchedule::Every {
                every_ms: 60_000,
                anchor_ms: None,
            },
            session_target: CronSessionTarget::Main,
            wake_mode: CronWakeMode::Now,
            payload: CronPayload::SystemEvent {
                text: format!("hello from {name}"),
            },
            isolation: None,
        }
    }

    #[test]
    fn test_flush_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");

        let s1 = CronScheduler::new(true, Some(path.clone()));
        let job_a = s1.add(test_job_create("alpha")).unwrap();
        let job_b = s1.add(test_job_create("beta")).unwrap();

        // Simulate a running job so we can verify it gets cleared on load.
        s1.set_job_running_for_test(&job_a.id, Some(12345));

        // New scheduler loads from disk.
        let s2 = CronScheduler::new(true, Some(path));
        s2.load();

        let loaded = s2.list(true);
        assert_eq!(loaded.len(), 2);

        let a = loaded.iter().find(|j| j.id == job_a.id).unwrap();
        assert_eq!(a.name, "alpha");
        assert_eq!(a.description.as_deref(), Some("desc for alpha"));
        assert!(
            a.state.running_at_ms.is_none(),
            "running_at_ms should be cleared on load"
        );
        assert!(
            a.state.next_run_at_ms.is_some(),
            "next_run_at_ms should be recomputed"
        );

        let b = loaded.iter().find(|j| j.id == job_b.id).unwrap();
        assert_eq!(b.name, "beta");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");

        let s = CronScheduler::new(true, Some(path));
        s.load(); // should not panic or error
        assert!(s.list(true).is_empty());
    }

    #[test]
    fn test_load_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"this is not json!!!").unwrap();

        let s = CronScheduler::new(true, Some(path));
        s.load(); // should not panic
        assert!(s.list(true).is_empty());
    }

    #[test]
    fn test_remove_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");

        let s1 = CronScheduler::new(true, Some(path.clone()));
        let job = s1.add(test_job_create("to-remove")).unwrap();
        s1.remove(&job.id);

        // Fresh load should see an empty list.
        let s2 = CronScheduler::new(true, Some(path));
        s2.load();
        assert!(s2.list(true).is_empty());
    }

    #[test]
    fn test_update_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");

        let s1 = CronScheduler::new(true, Some(path.clone()));
        let job = s1.add(test_job_create("original")).unwrap();
        s1.update(
            &job.id,
            CronJobPatch {
                name: Some("renamed".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        let s2 = CronScheduler::new(true, Some(path));
        s2.load();
        let loaded = s2.list(true);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "renamed");
    }

    // ---------------------------------------------------------------
    // Timezone tests
    // ---------------------------------------------------------------

    #[test]
    fn test_compute_next_run_cron_tz_none_unchanged() {
        // tz=None should behave identically to the pre-timezone code path.
        let now_dt = utc(2025, 6, 15, 10, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "30 10 * * *".to_string(),
            tz: None,
        };
        let next = compute_next_run(&schedule, now).unwrap();
        let expected = utc(2025, 6, 15, 10, 30).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_compute_next_run_cron_tz_utc_unchanged() {
        // tz=Some("UTC") should be identical to tz=None.
        let now_dt = utc(2025, 6, 15, 10, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule_none = CronSchedule::Cron {
            expr: "30 10 * * *".to_string(),
            tz: None,
        };
        let schedule_utc = CronSchedule::Cron {
            expr: "30 10 * * *".to_string(),
            tz: Some("UTC".to_string()),
        };
        assert_eq!(
            compute_next_run(&schedule_none, now),
            compute_next_run(&schedule_utc, now),
        );
    }

    #[test]
    fn test_compute_next_run_cron_eastern_winter() {
        // "0 9 * * *" with tz=America/New_York in January.
        // 9 AM ET in winter (EST = UTC-5) → 14:00 UTC.
        let now_dt = utc(2025, 1, 15, 0, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "0 9 * * *".to_string(),
            tz: Some("America/New_York".to_string()),
        };
        let next = compute_next_run(&schedule, now).unwrap();
        let expected = utc(2025, 1, 15, 14, 0).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_compute_next_run_cron_eastern_summer() {
        // "0 9 * * *" with tz=America/New_York in July.
        // 9 AM ET in summer (EDT = UTC-4) → 13:00 UTC.
        let now_dt = utc(2025, 7, 15, 0, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "0 9 * * *".to_string(),
            tz: Some("America/New_York".to_string()),
        };
        let next = compute_next_run(&schedule, now).unwrap();
        let expected = utc(2025, 7, 15, 13, 0).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_compute_next_run_cron_invalid_tz() {
        // Bad timezone string → None.
        let now_dt = utc(2025, 6, 15, 0, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "0 9 * * *".to_string(),
            tz: Some("Not/A_Timezone".to_string()),
        };
        assert_eq!(compute_next_run(&schedule, now), None);
    }

    #[test]
    fn test_compute_next_run_cron_spring_forward_skip() {
        // US spring forward 2025: Mar 9 at 2:00 AM ET clocks jump to 3:00 AM.
        // "30 2 * * *" with tz=America/New_York — 2:30 AM doesn't exist on Mar 9.
        // The next valid 2:30 AM should be Mar 10.
        let now_dt = utc(2025, 3, 9, 0, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "30 2 * * *".to_string(),
            tz: Some("America/New_York".to_string()),
        };
        let next = compute_next_run(&schedule, now).unwrap();
        // Mar 10 is EDT (UTC-4): 2:30 AM EDT → 06:30 UTC.
        let expected = utc(2025, 3, 10, 6, 30).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_compute_next_run_cron_fall_back_first_only() {
        // US fall back 2025: Nov 2 at 2:00 AM ET clocks go back to 1:00 AM.
        // "30 1 * * *" with tz=America/New_York.
        // 1:30 AM EDT (first) = 05:30 UTC. 1:30 AM EST (second) = 06:30 UTC.
        // We should fire at the first occurrence: 05:30 UTC.
        let now_dt = utc(2025, 11, 2, 0, 0);
        let now = now_dt.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "30 1 * * *".to_string(),
            tz: Some("America/New_York".to_string()),
        };
        let next = compute_next_run(&schedule, now).unwrap();
        let expected = utc(2025, 11, 2, 5, 30).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_compute_next_run_cron_fall_back_no_double() {
        // After the first 1:30 AM fires (05:30 UTC on Nov 2), the next
        // occurrence should be Nov 3, not the second 1:30 AM (06:30 UTC).
        // Nov 3 is regular EST: 1:30 AM EST = 06:30 UTC.
        let after_first = utc(2025, 11, 2, 5, 30);
        let now = after_first.timestamp_millis() as u64;
        let schedule = CronSchedule::Cron {
            expr: "30 1 * * *".to_string(),
            tz: Some("America/New_York".to_string()),
        };
        let next = compute_next_run(&schedule, now).unwrap();
        let expected = utc(2025, 11, 3, 6, 30).timestamp_millis() as u64;
        assert_eq!(next, expected);
    }

    #[test]
    fn test_in_memory_no_writes() {
        let s = CronScheduler::in_memory();
        assert!(
            s.persist_path.is_none(),
            "in_memory should have no persist_path"
        );

        // All mutation paths succeed without disk I/O.
        let job = s.add(test_job_create("ghost")).unwrap();
        s.update(
            &job.id,
            CronJobPatch {
                name: Some("updated".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        s.run(&job.id, Some(CronRunMode::Force)).unwrap();
        s.mark_run_finished(&job.id, CronJobStatus::Ok, 1, None)
            .unwrap();
        s.remove(&job.id);
    }

    #[test]
    fn test_run_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");

        let s1 = CronScheduler::new(true, Some(path.clone()));
        let job = s1.add(test_job_create("runner")).unwrap();
        s1.run(&job.id, Some(CronRunMode::Force)).unwrap();

        // Read raw JSON to verify running_at_ms was persisted (load() would
        // clear it, so we inspect the file directly).
        let data = fs::read(&path).unwrap();
        let on_disk: Vec<CronJob> = serde_json::from_slice(&data).unwrap();
        let disk_job = on_disk.iter().find(|j| j.id == job.id).unwrap();
        assert!(
            disk_job.state.running_at_ms.is_some(),
            "run() should persist running_at_ms"
        );
    }

    #[test]
    fn test_mark_run_finished_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cron").join("jobs.json");

        let s1 = CronScheduler::new(true, Some(path.clone()));
        let job = s1.add(test_job_create("finisher")).unwrap();
        s1.run(&job.id, Some(CronRunMode::Force)).unwrap();
        s1.mark_run_finished(&job.id, CronJobStatus::Ok, 100, None)
            .unwrap();

        // Load in fresh scheduler — last_status and last_duration_ms survive.
        let s2 = CronScheduler::new(true, Some(path));
        s2.load();
        let loaded = s2.get(&job.id).unwrap();
        assert_eq!(loaded.state.last_status, Some(CronJobStatus::Ok));
        assert_eq!(loaded.state.last_duration_ms, Some(100));
    }
}
