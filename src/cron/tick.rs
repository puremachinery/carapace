//! Cron tick loop.
//!
//! Background task that periodically scans for due cron jobs and executes them.

use std::sync::Arc;
use std::time::Duration;

use crate::cron::executor::{execute_payload, CronRunOutcome};
use crate::cron::{CronJobStatus, CronRunMode};
use crate::server::ws::{AgentRunStatus, WsServerState};

/// Run the cron tick loop.
///
/// Periodically checks for due jobs and spawns their execution.
/// Stops when a shutdown signal is received.
pub async fn cron_tick_loop(
    state: Arc<WsServerState>,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => break,
        }

        if *shutdown.borrow() {
            break;
        }

        let due_ids = state.cron_scheduler.get_due_job_ids();

        for job_id in due_ids {
            let result = match state.cron_scheduler.run(&job_id, Some(CronRunMode::Due)) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(job_id = %job_id, error = %e, "cron run error");
                    continue;
                }
            };

            if !result.ran {
                continue;
            }

            if let Some(payload) = result.payload {
                let state = state.clone();
                let job_id = result.job_id.clone();
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    let outcome = execute_payload(&job_id, &payload, &state).await;

                    // For AgentTurn payloads, wait for the agent run to actually complete
                    // before reporting the cron job status.
                    let (status, error) = match outcome {
                        Ok(CronRunOutcome::Spawned { run_id }) => {
                            let waiter = {
                                let mut registry = state.agent_run_registry.lock();
                                registry.add_waiter(&run_id)
                            };
                            if let Some(rx) = waiter {
                                match rx.await {
                                    Ok(result) => match result.status {
                                        AgentRunStatus::Completed => (CronJobStatus::Ok, None),
                                        AgentRunStatus::Failed => {
                                            (CronJobStatus::Error, result.error)
                                        }
                                        AgentRunStatus::Cancelled => (
                                            CronJobStatus::Error,
                                            Some("agent run cancelled".to_string()),
                                        ),
                                        _ => (CronJobStatus::Ok, None),
                                    },
                                    Err(_) => (
                                        CronJobStatus::Error,
                                        Some("agent run waiter dropped".to_string()),
                                    ),
                                }
                            } else {
                                // Run not found in registry (shouldn't happen)
                                (
                                    CronJobStatus::Error,
                                    Some("agent run not found".to_string()),
                                )
                            }
                        }
                        Ok(CronRunOutcome::Broadcast) => (CronJobStatus::Ok, None),
                        Err(e) => (CronJobStatus::Error, Some(e)),
                    };

                    let duration_ms = start.elapsed().as_millis() as u64;

                    if let Err(e) =
                        state
                            .cron_scheduler
                            .mark_run_finished(&job_id, status, duration_ms, error)
                    {
                        tracing::warn!(
                            job_id = %job_id,
                            error = %e,
                            "failed to mark cron run finished"
                        );
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::{CronJobCreate, CronPayload, CronSchedule, CronSessionTarget, CronWakeMode};
    use crate::server::ws::{WsServerConfig, WsServerState};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_tick_loop_shutdown() {
        let state = Arc::new(WsServerState::new(WsServerConfig::default()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(async move {
            cron_tick_loop(state, Duration::from_secs(60), shutdown_rx).await;
        });

        // Signal shutdown
        let _ = shutdown_tx.send(true);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("tick loop should exit on shutdown")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_tick_loop_executes_due_jobs() {
        let state = Arc::new(WsServerState::new(WsServerConfig::default()));

        // Add a job with Every schedule so it gets a valid next_run_at_ms
        let job = state
            .cron_scheduler
            .add(CronJobCreate {
                name: "Due Job".to_string(),
                agent_id: None,
                description: None,
                enabled: true,
                delete_after_run: None,
                schedule: CronSchedule::Every {
                    every_ms: 1_000_000_000,
                    anchor_ms: Some(1),
                },
                session_target: CronSessionTarget::Main,
                wake_mode: CronWakeMode::Now,
                payload: CronPayload::SystemEvent {
                    text: "tick test".to_string(),
                },
                isolation: None,
            })
            .unwrap();

        // Manually set next_run_at_ms to a past time so it's due
        {
            let mut jobs = state.cron_scheduler.jobs.write();
            let j = jobs.iter_mut().find(|j| j.id == job.id).unwrap();
            j.state.next_run_at_ms = Some(1);
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let st = state.clone();

        let handle = tokio::spawn(async move {
            cron_tick_loop(st, Duration::from_millis(50), shutdown_rx).await;
        });

        // Let it tick once
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = shutdown_tx.send(true);
        let _ = handle.await;

        // Allow time for async spawned task to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The tick loop calls run() which returns payload, then spawns execution.
        // Since SystemEvent execution is fast, mark_run_finished should have been called.
        let runs = state.cron_scheduler.runs(None, None);
        assert!(!runs.is_empty(), "expected at least one run log entry");
    }
}
