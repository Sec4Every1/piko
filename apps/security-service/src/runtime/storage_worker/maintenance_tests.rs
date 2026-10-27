//! Isolated queues and synthetic archives; no installed service or sensors.
use super::*;
use piko_event_schema::{RawEvidence, SecurityEvent};
use std::error::Error;
use std::fs;
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

fn queued_client(
    enabled: bool,
) -> (
    StorageClient,
    mpsc::Receiver<Job>,
    tokio::sync::watch::Sender<ArchiveMaintenanceStatus>,
) {
    let (sender, receiver) = mpsc::channel(1);
    let (verifier, _) = mpsc::channel(1);
    let (_, archive) = tokio::sync::watch::channel(ArchiveTelemetry::default());
    let (status, maintenance) = tokio::sync::watch::channel(ArchiveMaintenanceStatus {
        enabled,
        ..Default::default()
    });
    (
        StorageClient {
            sender,
            verifier,
            archive,
            maintenance,
            maintenance_queued: Arc::new(AtomicBool::new(false)),
        },
        receiver,
        status,
    )
}

#[test]
fn disabled_maintenance_never_enters_the_writer_queue() -> TestResult {
    let (client, mut jobs, _status) = queued_client(false);
    client.try_maintain()?;
    assert!(matches!(
        jobs.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(!client.maintenance_queued.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn duplicate_maintenance_requests_share_one_queue_slot() -> TestResult {
    let (client, mut jobs, _status) = queued_client(true);
    client.try_maintain()?;
    client.try_maintain()?;
    assert!(matches!(jobs.try_recv(), Ok(Job::Maintain)));
    assert!(matches!(
        jobs.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    Ok(())
}

#[test]
fn queue_refusal_resets_the_flag_so_a_later_tick_can_retry() -> TestResult {
    let (client, mut jobs, _status) = queued_client(true);
    let append = client.try_append(Vec::new())?;
    assert!(client.try_maintain().is_err());
    assert!(!client.maintenance_queued.load(Ordering::Acquire));
    assert!(matches!(jobs.try_recv(), Ok(Job::Append { .. })));
    client.try_maintain()?;
    assert!(matches!(jobs.try_recv(), Ok(Job::Maintain)));
    drop(append);
    Ok(())
}

#[test]
fn closed_worker_discards_cached_success_metrics() {
    let (client, jobs, status) = queued_client(true);
    status.send_replace(ArchiveMaintenanceStatus {
        enabled: true,
        state: "completed_batch".into(),
        sampled_at_unix_ms: Some(100),
        scanned: 1,
        changed: 1,
        logical_bytes_saved: 512,
        cycle_complete: true,
        detail: None,
    });
    drop(status);
    drop(jobs);
    let unavailable = client.maintenance_status();
    assert_eq!(unavailable.state, "blocked");
    assert!(unavailable.sampled_at_unix_ms.is_none());
    assert_eq!(
        (
            unavailable.scanned,
            unavailable.changed,
            unavailable.logical_bytes_saved
        ),
        (0, 0, 0)
    );
    assert!(!unavailable.cycle_complete);
    assert!(unavailable.detail.is_some());
    assert!(client.try_maintain().is_err());
    assert!(!client.maintenance_queued.load(Ordering::Acquire));
}

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn completed(
    status: &mut tokio::sync::watch::Receiver<ArchiveMaintenanceStatus>,
) -> Result<ArchiveMaintenanceStatus, Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            status.changed().await?;
            let value = status.borrow_and_update().clone();
            if value.state == "blocked" {
                return Err(format!("maintenance blocked: {:?}", value.detail).into());
            }
            if value.state == "completed_batch" {
                return Ok(value);
            }
        }
    })
    .await?
}

#[tokio::test]
async fn real_worker_scans_stored_payload_then_finishes_without_evidence_loss() -> TestResult {
    let directory = Directory(
        std::env::temp_dir().join(format!("piko-maintenance-fixture-{}", Uuid::new_v4())),
    );
    fs::create_dir(&directory.0)?;
    let path = directory.0.join("events.db");
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    let raw = RawEvidence {
        evidence_id: Uuid::new_v4(),
        source: "fixture".into(),
        content_type: "application/octet-stream".into(),
        observed_at_unix_ms: 100,
        bytes: vec![120; 4096],
    };
    let mut event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), 1, 100, 1);
    event.raw_evidence_reference = Some(raw.evidence_id);
    store.append_records(&[EventRecord {
        event,
        raw_evidence: Some(raw.clone()),
    }])?;
    let before = store.verify_integrity()?;
    drop(store);
    let (client, _, count, _) =
        StorageClient::start_with_maintenance(path.clone(), StorageConfig::default(), true).await?;
    assert_eq!(count, 1);
    let mut status = client.maintenance.clone();
    status.borrow_and_update();
    client.try_maintain()?;
    let first = completed(&mut status).await?;
    // The normal append path already compressed this evidence. A maintenance
    // scan must report the no-op truthfully rather than claiming new savings.
    assert_eq!((first.scanned, first.changed), (1, 0));
    assert_eq!(first.logical_bytes_saved, 0);
    assert!(!first.cycle_complete);
    // Watch notifications do not acknowledge the queue flag reset. An append
    // reply is a writer barrier, avoiding sleeps or polling between passes.
    client.try_append(Vec::new())?.await??;
    client.try_maintain()?;
    let finished = completed(&mut status).await?;
    assert!(finished.cycle_complete);
    assert_eq!((finished.scanned, finished.changed), (0, 0));
    drop(client);
    tokio::time::timeout(Duration::from_secs(10), async {
        while status.changed().await.is_ok() {}
    })
    .await?;
    let reopened = SqliteEventStore::reader(&path, StorageConfig::default())?;
    assert_eq!(reopened.verify_integrity()?, before);
    assert_eq!(
        reopened
            .raw_evidence(raw.evidence_id)?
            .ok_or("missing evidence")?
            .bytes,
        raw.bytes
    );
    drop(reopened);
    Ok(())
}
