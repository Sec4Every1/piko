use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use piko_event_schema::EventRecord;
use piko_event_storage::{ArchiveMaintenanceStatus, SqliteEventStore, StorageConfig, StorageError};
use piko_ipc::{ApiData, ApiError, Command};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

const STORAGE_QUEUE_CAPACITY: usize = 8;
fn bounded_detail(mut detail: String) -> String {
    let mut end = detail.len().min(2048);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail
}
struct VerificationJob {
    deadline: Instant,
    reply: oneshot::Sender<Result<ApiData, ApiError>>,
}
pub type AppendResult = Result<u64, String>;

enum Job {
    Maintain,
    Append {
        batch: Vec<EventRecord>,
        reply: oneshot::Sender<AppendResult>,
    },
    Read {
        command: Command,
        deadline: Instant,
        reply: oneshot::Sender<Result<ApiData, ApiError>>,
    },
}

#[derive(Clone, Default)]
pub struct ArchiveTelemetry {
    pub usage: Option<piko_common_model::ArchiveUsage>,
    pub error: Option<String>,
}
fn archive_sample(store: &SqliteEventStore, budget: u64) -> ArchiveTelemetry {
    let result = (|| -> Result<piko_common_model::ArchiveUsage, String> {
        let (database_bytes, total_bytes) = store.archive_bytes().map_err(|e| e.to_string())?;
        let sampled_at_unix_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis(),
        )
        .map_err(|e| e.to_string())?;
        Ok(piko_common_model::ArchiveUsage {
            sampled_at_unix_ms,
            budget_bytes: budget,
            database_limit_bytes: store.database_limit_bytes().map_err(|e| e.to_string())?,
            database_bytes,
            database_active_bytes: Some(store.active_database_bytes().map_err(|e| e.to_string())?),
            retention_months: store.retention_months(),
            expired_events: store.expired_events().map_err(|e| e.to_string())?,
            total_bytes,
        })
    })();
    match result {
        Ok(usage) => ArchiveTelemetry {
            usage: Some(usage),
            error: None,
        },
        Err(error) => ArchiveTelemetry {
            usage: None,
            error: Some(error),
        },
    }
}
#[derive(Clone)]
pub struct StorageClient {
    sender: mpsc::Sender<Job>,
    verifier: mpsc::Sender<VerificationJob>,
    archive: tokio::sync::watch::Receiver<ArchiveTelemetry>,
    maintenance: tokio::sync::watch::Receiver<ArchiveMaintenanceStatus>,
    maintenance_queued: Arc<AtomicBool>,
}

impl StorageClient {
    #[cfg(test)]
    pub async fn start(
        path: PathBuf,
        config: StorageConfig,
    ) -> Result<(Self, Uuid, u64, std::collections::HashMap<String, String>), String> {
        Self::start_with_maintenance(path, config, false).await
    }

    pub async fn start_with_maintenance(
        path: PathBuf,
        config: StorageConfig,
        enabled: bool,
    ) -> Result<(Self, Uuid, u64, std::collections::HashMap<String, String>), String> {
        let (sender, mut receiver) = mpsc::channel(STORAGE_QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let (archive_sender, archive) = tokio::sync::watch::channel(ArchiveTelemetry::default());
        let (maintenance_sender, maintenance) =
            tokio::sync::watch::channel(ArchiveMaintenanceStatus {
                enabled,
                state: "waiting".into(),
                ..Default::default()
            });
        let maintenance_queued = Arc::new(AtomicBool::new(false));
        let worker_maintenance_queued = maintenance_queued.clone();
        let budget = config.max_disk_bytes;
        let verification_path = path.clone();
        let verification_config = config.clone();
        let (verifier, mut verification_jobs) = mpsc::channel::<VerificationJob>(1);
        std::thread::Builder::new()
            .name("piko-integrity".into())
            .spawn(move || {
                while let Some(job) = verification_jobs.blocking_recv() {
                    if job.reply.is_closed() {
                        continue;
                    }
                    if Instant::now() >= job.deadline {
                        let _ = job.reply.send(Err(api_error(
                            "request_expired",
                            "verification expired in queue",
                        )));
                        continue;
                    }
                    let result =
                        SqliteEventStore::reader(&verification_path, verification_config.clone())
                            .and_then(|reader| {
                                reader.set_operation_deadline(Some(job.deadline))?;
                                reader.verify_integrity()
                            });
                    let result = if Instant::now() >= job.deadline {
                        Err(api_error(
                            "request_timeout",
                            "verification exceeded its bounded deadline",
                        ))
                    } else {
                        result.map(ApiData::Integrity).map_err(storage_error)
                    };
                    let _ = job.reply.send(result);
                }
            })
            .map_err(|e| e.to_string())?;
        std::thread::Builder::new()
            .name("piko-storage".into())
            .spawn(move || {
                let store = SqliteEventStore::open(path, config)
                    .and_then(|store| store.count().map(|count| (store, count)));
                let (mut store, mut stored_count) = match store {
                    Ok(pair) => pair,
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                let mut checkpoints = std::collections::HashMap::new();
                for channel in piko_win_platform::event_log::CHANNELS {
                    let sensor = format!("windows.event_log.{channel}");
                    match store.latest_sensor_event(&sensor) {
                        Ok(Some(event)) => {
                            if let Some(bookmark) = event.integrity_metadata.source_integrity {
                                checkpoints.insert(sensor, bookmark);
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let _ = ready_sender.send(Err(error.to_string()));
                            return;
                        }
                    }
                }
                archive_sender.send_replace(archive_sample(&store, budget));
                if ready_sender
                    .send(Ok((store.host_id(), stored_count, checkpoints)))
                    .is_err()
                {
                    return;
                }
                // Cursor is intentionally local: a restart safely rescans preserved rows.
                let mut maintenance_cursor = 0;
                while let Some(job) = receiver.blocking_recv() {
                    match job {
                        Job::Maintain => {
                            // A maintenance request yields to already queued collection/read work.
                            if !receiver.is_empty() {
                                let mut status = maintenance_sender.borrow().clone();
                                status.state = "waiting".into();
                                status.detail =
                                    Some("waiting for the storage queue to become idle".into());
                                maintenance_sender.send_replace(status);
                                worker_maintenance_queued.store(false, Ordering::Release);
                                continue;
                            }
                            maintenance_sender.send_replace(ArchiveMaintenanceStatus {
                                enabled,
                                state: "running".into(),
                                ..Default::default()
                            });
                            // Use the append writer and its original protection identity only.
                            let result = store
                                .set_operation_deadline(None)
                                .and_then(|()| store.maintain_archive_batch(maintenance_cursor));
                            let sampled_at_unix_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .and_then(|time| i64::try_from(time.as_millis()).ok());
                            let status = match result {
                                Ok((next_cursor, scanned, changed, logical_bytes_saved)) => {
                                    let cycle_complete = scanned == 0;
                                    maintenance_cursor =
                                        if cycle_complete { 0 } else { next_cursor };
                                    ArchiveMaintenanceStatus {
                                        enabled,
                                        state: "completed_batch".into(),
                                        sampled_at_unix_ms,
                                        scanned,
                                        changed,
                                        logical_bytes_saved,
                                        cycle_complete,
                                        detail: None,
                                    }
                                }
                                Err(error) => ArchiveMaintenanceStatus {
                                    enabled,
                                    state: "blocked".into(),
                                    sampled_at_unix_ms,
                                    detail: Some(bounded_detail(error.to_string())),
                                    ..Default::default()
                                },
                            };
                            archive_sender.send_replace(archive_sample(&store, budget));
                            maintenance_sender.send_replace(status);
                            worker_maintenance_queued.store(false, Ordering::Release);
                        }
                        Job::Append { batch, reply } => {
                            if let Err(error) = store.set_operation_deadline(None) {
                                let _ = reply.send(Err(error.to_string()));
                                continue;
                            }
                            if let Some(months) = store.retention_months() {
                                let maintenance = (|| -> Result<(), StorageError> {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map_err(|_| StorageError::Configuration)?
                                        .as_millis();
                                    let cutoff = piko_event_storage::calendar_cutoff(
                                        i64::try_from(now)
                                            .map_err(|_| StorageError::Configuration)?,
                                        months,
                                    )?;
                                    for _ in 0..4 {
                                        if store.expire_before(cutoff)? == 0 {
                                            break;
                                        }
                                    }
                                    Ok(())
                                })();
                                if let Err(error) = maintenance {
                                    archive_sender.send_replace(archive_sample(&store, budget));
                                    let _ = reply.send(Err(error.to_string()));
                                    continue;
                                }
                            }
                            let result = store
                                .append_records(&batch)
                                .and_then(|()| {
                                    stored_count = if store.retention_months().is_some() {
                                        store.count()?
                                    } else {
                                        stored_count.saturating_add(batch.len() as u64)
                                    };
                                    Ok(stored_count)
                                })
                                .map_err(|error| error.to_string());
                            archive_sender.send_replace(archive_sample(&store, budget));
                            let _ = reply.send(result);
                        }
                        Job::Read {
                            command,
                            deadline,
                            reply,
                        } => {
                            // A client disconnect or deadline never starts obsolete work.
                            if reply.is_closed() {
                                continue;
                            }
                            if Instant::now() >= deadline {
                                let _ = reply.send(Err(api_error(
                                    "request_expired",
                                    "storage request expired in queue",
                                )));
                                continue;
                            }
                            if let Err(error) = store.set_operation_deadline(Some(deadline)) {
                                let _ = reply.send(Err(storage_error(error)));
                                continue;
                            }
                            let result = match command {
                                Command::ListAlerts => store.alerts().map(ApiData::Alerts),
                                Command::GetEvidence { evidence_id } => {
                                    store.raw_evidence(evidence_id).map(ApiData::Evidence)
                                }
                                Command::ListEvents(query) => {
                                    store.query(&query).map(ApiData::Events)
                                }
                                Command::GetAuthenticationActivity(query) => store
                                    .authentication_activity(&query)
                                    .map(ApiData::AuthenticationActivity),
                                Command::GetInvestigation { process_instance } => {
                                    investigation_query(&store, process_instance, None)
                                }
                                Command::GetInvestigationWindow {
                                    process_instance,
                                    observed_from,
                                    observed_until,
                                } => investigation_query(
                                    &store,
                                    process_instance,
                                    Some((observed_from, observed_until)),
                                ),
                                Command::GetInvestigationPage {
                                    process_instance,
                                    observed_window,
                                    before,
                                } => investigation_page(
                                    &store,
                                    process_instance,
                                    observed_window,
                                    before,
                                ),
                                _ => {
                                    if let Err(error) = store.set_operation_deadline(None) {
                                        let _ = reply.send(Err(storage_error(error)));
                                        continue;
                                    }
                                    let _ = reply.send(Err(api_error(
                                        "invalid_command",
                                        "command uses a dedicated worker or runtime cache",
                                    )));
                                    continue;
                                }
                            };
                            let result = store.set_operation_deadline(None).and(result);
                            let result = if Instant::now() >= deadline {
                                Err(api_error(
                                    "request_timeout",
                                    "storage operation exceeded its deadline",
                                ))
                            } else {
                                result.map_err(storage_error)
                            };
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        let (host_id, count, checkpoints) = ready_receiver
            .await
            .map_err(|_| "storage worker stopped during startup".to_string())??;
        Ok((
            Self {
                sender,
                verifier,
                archive,
                maintenance,
                maintenance_queued,
            },
            host_id,
            count,
            checkpoints,
        ))
    }

    pub fn archive_metrics(&self) -> ArchiveTelemetry {
        self.archive.borrow().clone()
    }

    pub fn maintenance_status(&self) -> ArchiveMaintenanceStatus {
        let mut status = self.maintenance.borrow().clone();
        if self.maintenance.has_changed().is_err() {
            status.state = "blocked".into();
            status.sampled_at_unix_ms = None;
            status.scanned = 0;
            status.changed = 0;
            status.logical_bytes_saved = 0;
            status.cycle_complete = false;
            status.detail = Some(
                "storage worker is unavailable; cached maintenance outcome is not current".into(),
            );
        }
        status
    }

    pub fn try_maintain(&self) -> Result<(), String> {
        if !self.maintenance.borrow().enabled {
            return Ok(());
        }
        if self.maintenance_queued.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if let Err(error) = self.sender.try_send(Job::Maintain) {
            self.maintenance_queued.store(false, Ordering::Release);
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => "storage worker queue is full".into(),
                mpsc::error::TrySendError::Closed(_) => "storage worker is unavailable".into(),
            });
        }
        Ok(())
    }

    pub fn try_append(
        &self,
        batch: Vec<EventRecord>,
    ) -> Result<oneshot::Receiver<AppendResult>, String> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(Job::Append { batch, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => "storage worker queue is full".to_string(),
                mpsc::error::TrySendError::Closed(_) => "storage worker is unavailable".to_string(),
            })?;
        Ok(receiver)
    }

    pub async fn read(&self, command: Command, deadline: Instant) -> Result<ApiData, ApiError> {
        if Instant::now() >= deadline {
            return Err(api_error("request_expired", "request already expired"));
        }
        let (reply, receiver) = oneshot::channel();
        if matches!(&command, Command::VerifyStore) {
            self.verifier
                .try_send(VerificationJob { deadline, reply })
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => {
                        api_error("verification_busy", "bounded verification queue is full")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        api_error("verification_unavailable", "verification worker stopped")
                    }
                })?;
        } else {
            self.sender
                .try_send(Job::Read {
                    command,
                    deadline,
                    reply,
                })
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        api_error("storage_busy", "bounded storage queue is full")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        api_error("storage_unavailable", "storage worker stopped")
                    }
                })?;
        }
        tokio::time::timeout_at(deadline.into(), receiver)
            .await
            .map_err(|_| api_error("request_timeout", "storage operation exceeded its deadline"))?
            .map_err(|_| {
                api_error(
                    "storage_unavailable",
                    "storage worker stopped without a reply",
                )
            })?
    }
}

fn investigation_query(
    store: &SqliteEventStore,
    process_instance: Uuid,
    observed_window: Option<(i64, i64)>,
) -> Result<ApiData, StorageError> {
    let expression = investigation_expression(process_instance, observed_window)?;
    let cap = piko_security_core::MAX_INVESTIGATION_EVENTS;
    store
        .query(&piko_event_storage::EventQuery {
            expression: Some(expression),
            limit: cap + 1,
            ..Default::default()
        })
        .map(|events| {
            ApiData::Investigation(piko_security_core::investigate(
                process_instance,
                &events,
                events.len() > cap,
            ))
        })
}

fn investigation_page(
    store: &SqliteEventStore,
    process_instance: Uuid,
    window: Option<(i64, i64)>,
    before: Option<(i64, Uuid)>,
) -> Result<ApiData, StorageError> {
    if before.is_some_and(|(time, _)| {
        !(0..=8_640_000_000_000_000).contains(&time)
            || window.is_some_and(|(from, until)| time < from || time >= until)
    }) {
        return Err(StorageError::InvalidQuery);
    }
    let expression = investigation_expression(process_instance, window)?;
    let mut events = store.observation_page(&expression, before)?;
    let more = events.len() > 128;
    events.truncate(128);
    // Advance using the last queried event, even when admission rejects it.
    // Never skip the 129th lookahead row or infer a cursor from display sorting.
    let cursor = if more {
        events.last().map(|e| (e.observation_time, e.event_id))
    } else {
        None
    };
    let mut graph = piko_security_core::investigate(process_instance, &events, more);
    graph.observation_paging_available = true;
    graph.next_observation_cursor = cursor;
    Ok(ApiData::Investigation(graph))
}

fn investigation_expression(
    process_instance: Uuid,
    observed_window: Option<(i64, i64)>,
) -> Result<String, StorageError> {
    if let Some((observed_from, observed_until)) = observed_window {
        if observed_from < 0
            || observed_until <= observed_from
            || observed_until > 8_640_000_000_000_000
        {
            return Err(StorageError::InvalidQuery);
        }
    }
    let mut expression = format!("(process.instance = \"{process_instance}\" OR process.parent_instance = \"{process_instance}\") AND sensor.id = \"windows.observations\" AND (event.type = \"process.snapshot.observed\" OR event.type = \"process.snapshot.changed\" OR event.type = \"network.snapshot.observed\" OR event.type = \"network.snapshot.changed\" OR event.type = \"network.udp.snapshot.observed\" OR event.type = \"network.udp.snapshot.changed\")");
    if let Some((observed_from, observed_until)) = observed_window {
        // Static numeric fields compile to bound SQLite values. Apply the
        // observation-time window in WHERE before the existing bounded LIMIT.
        expression.push_str(&format!(
            " AND event.observed_at >= {observed_from} AND event.observed_at < {observed_until}"
        ));
    }
    Ok(expression)
}

pub fn api_error(code: &str, message: &str) -> ApiError {
    ApiError {
        code: code.into(),
        message: message.into(),
    }
}

fn storage_error(error: StorageError) -> ApiError {
    let code = match &error {
        StorageError::ProtectionPolicy(_) => "evidence_protection_unavailable",
        StorageError::InvalidQuery => "invalid_query",
        StorageError::QuerySyntax(_) => "query_syntax",
        StorageError::QueryResultTooLarge => "query_result_too_large",
        StorageError::Corrupt(_) | StorageError::Schema(_) | StorageError::Json(_) => {
            "evidence_corrupt"
        }
        StorageError::DiskBudgetExceeded => "disk_budget_exhausted",
        _ => "storage_error",
    };
    api_error(code, &error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn closed_and_full_worker_queues_fail_explicitly() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::channel(1);
        let (_, archive) = tokio::sync::watch::channel(ArchiveTelemetry::default());
        let (verifier, _verification_jobs) = mpsc::channel(1);
        let client = StorageClient {
            sender,
            verifier,
            archive,
            maintenance: tokio::sync::watch::channel(ArchiveMaintenanceStatus::default()).1,
            maintenance_queued: Arc::new(AtomicBool::new(false)),
        };
        let first = client.try_append(Vec::new())?;
        assert!(client.try_append(Vec::new()).is_err());
        drop(receiver);
        assert!(client.try_append(Vec::new()).is_err());
        drop(first);
        Ok(())
    }

    #[test]
    fn expired_request_is_rejected_without_enqueueing() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (sender, mut receiver) = mpsc::channel(1);
            let (_, archive) = tokio::sync::watch::channel(ArchiveTelemetry::default());
            let (verifier, _verification_jobs) = mpsc::channel(1);
            let client = StorageClient {
                sender,
                verifier,
                archive,
                maintenance: tokio::sync::watch::channel(ArchiveMaintenanceStatus::default()).1,
                maintenance_queued: Arc::new(AtomicBool::new(false)),
            };
            let error = client
                .read(
                    Command::VerifyStore,
                    Instant::now() - Duration::from_secs(1),
                )
                .await;
            assert!(matches!(error, Err(error) if error.code == "request_expired"));
            assert!(receiver.try_recv().is_err());
            Ok(())
        })
    }
    #[test]
    fn verification_bypasses_a_full_writer_queue() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (sender, mut jobs) = mpsc::channel(1);
            let (verifier, mut checks) = mpsc::channel::<VerificationJob>(1);
            let (_, archive) = tokio::sync::watch::channel(ArchiveTelemetry::default());
            let client = StorageClient {
                sender,
                verifier,
                archive,
                maintenance: tokio::sync::watch::channel(ArchiveMaintenanceStatus::default()).1,
                maintenance_queued: Arc::new(AtomicBool::new(false)),
            };
            let append = client.try_append(Vec::new())?;
            let call = client.read(
                Command::VerifyStore,
                Instant::now() + Duration::from_secs(1),
            );
            let answer = async {
                let job = checks.recv().await.ok_or("missing dedicated job")?;
                job.reply
                    .send(Ok(ApiData::Integrity(
                        piko_event_storage::IntegrityReport {
                            verified_events: 0,
                            head_hash: None,
                            externally_anchored: false,
                            expired_events: 0,
                        },
                    )))
                    .map_err(|_| "closed reply")?;
                Ok::<(), Box<dyn std::error::Error>>(())
            };
            let (result, answer) = tokio::join!(call, answer);
            answer?;
            assert!(matches!(result, Ok(ApiData::Integrity(_))));
            assert!(matches!(jobs.try_recv(), Ok(Job::Append { .. })));
            drop(append);
            Ok(())
        })
    }
}
#[tokio::test]
async fn parent_lifetime_survives_storage_query_and_ipc_response(
) -> Result<(), Box<dyn std::error::Error>> {
    use piko_common_model::ObservedProcess;
    use piko_event_schema::SecurityEvent;
    let path = std::env::temp_dir().join(format!("piko-parent-query-{}.db", Uuid::new_v4()));
    let (client, host, _, _) = StorageClient::start(path, StorageConfig::default()).await?;
    let parent = ObservedProcess {
        instance_id: None,
        pid: 7,
        parent_pid: 0,
        name: "launcher.exe".into(),
        executable: Some("C:\\Example\\launcher.exe".into()),
        creation_filetime: Some(132_000_000_000_000_001),
        sid: None,
        session_id: Some(1),
        access_error: None,
    };
    let mut child = parent.clone();
    child.pid = 42;
    child.parent_pid = 7;
    child.creation_filetime = Some(133_000_000_000_000_001);
    child.name = "example.exe".into();
    let instance =
        piko_win_sensors::process_instance(host, &child).ok_or("missing child identity")?;
    let record = piko_win_sensors::normalize_observation(
        piko_win_sensors::Observation {
            transition: "observed",
            at: 1_700_000_000_000,
            process: Some(child),
            parent: Some(parent),
            connection: None,
            udp: None,
        },
        SecurityEvent::heartbeat(host, Uuid::new_v4(), 1, 1_700_000_000_001, 1),
    )?;
    let event_id = record.event.event_id;
    let evidence_id = record
        .event
        .raw_evidence_reference
        .ok_or("missing raw evidence")?;
    assert_eq!(client.try_append(vec![record])?.await??, 1);
    let answer = client
        .read(
            Command::GetInvestigation {
                process_instance: instance,
            },
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .map_err(|e| e.message)?;
    let answer: ApiData = serde_json::from_slice(&serde_json::to_vec(&answer)?)?;
    let ApiData::Investigation(graph) = answer else {
        return Err("unexpected IPC response".into());
    };
    assert_eq!(graph.events_considered, 1);
    let edge = graph
        .edges
        .iter()
        .find(|e| e.relation == "observed_parent")
        .ok_or("missing parent edge")?;
    assert_eq!(edge.event_ids, [event_id]);
    assert_eq!(edge.evidence_ids, [evidence_id]);
    assert_eq!(
        graph
            .nodes
            .iter()
            .find(|n| n.id == edge.target)
            .ok_or("missing parent node")?
            .label,
        "C:\\Example\\launcher.exe"
    );
    Ok(())
}

#[tokio::test]
async fn calendar_retention_runs_before_append_and_reports_retained_count(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("piko-worker-retention-{}.db", Uuid::new_v4()));
    let (client, host, _, _) = StorageClient::start(
        path,
        StorageConfig {
            retention_months: Some(12),
            ..Default::default()
        },
    )
    .await?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let runtime = Uuid::new_v4();
    let mut old = piko_event_schema::SecurityEvent::heartbeat(host, runtime, 1, now, 1);
    old.ingestion_time = piko_event_storage::calendar_cutoff(now, 13)?;
    assert_eq!(
        client
            .try_append(vec![EventRecord {
                event: old,
                raw_evidence: None
            }])?
            .await??,
        1
    );
    let recent = piko_event_schema::SecurityEvent::heartbeat(host, runtime, 2, now, 2);
    assert_eq!(
        client
            .try_append(vec![EventRecord {
                event: recent,
                raw_evidence: None
            }])?
            .await??,
        1
    );
    let answer = client
        .read(
            Command::VerifyStore,
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .map_err(|e| e.message)?;
    let ApiData::Integrity(report) = answer else {
        return Err("unexpected response".into());
    };
    assert_eq!((report.verified_events, report.expired_events), (1, 1));
    assert_eq!(
        client
            .archive_metrics()
            .usage
            .ok_or("missing archive metrics")?
            .retention_months,
        Some(12)
    );
    Ok(())
}

#[cfg(test)]
mod history_tests;

#[cfg(test)]
mod maintenance_tests;
