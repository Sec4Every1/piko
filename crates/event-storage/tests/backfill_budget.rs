use piko_event_schema::{EventTarget, SecurityEvent};
use piko_event_storage::{SqliteEventStore, StorageConfig, StorageError};
use rusqlite::{Connection, OpenFlags};
use std::{error::Error, fs, path::PathBuf};
use uuid::Uuid;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = std::env::temp_dir().join(format!("piko-backfill-{}", Uuid::new_v4()));
        fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
    fn database(&self) -> PathBuf {
        self.0.join("events.db")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn account_event(host: Uuid, runtime: Uuid, sequence: u64, supported: bool) -> SecurityEvent {
    let mut event = SecurityEvent::heartbeat(host, runtime, sequence, 100, sequence);
    event.sensor_id = "windows.event_log.Security".into();
    event.event_category = "windows_event_log".into();
    event.event_type = "windows.event_log.4720".into();
    let provider = if supported {
        "Microsoft-Windows-Security-Auditing"
    } else {
        "Unsupported-Provider"
    };
    event.target = Some(EventTarget {
        kind: "windows_event_record".into(),
        identifier: format!("Security:{provider}:{sequence}"),
    });
    event
}

type Annotation = (String, String, Vec<u8>);
fn annotations(db: &Connection) -> Result<Vec<Annotation>, rusqlite::Error> {
    db.prepare("SELECT id,event_id,payload FROM detections ORDER BY id")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect()
}

#[test]
fn backfill_crosses_empty_batches_and_reopens_idempotently() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let config = StorageConfig::default();
    let mut writer = SqliteEventStore::open(fixture.database(), config.clone())?;
    let host = writer.host_id();
    let runtime = Uuid::new_v4();
    // A complete first scan batch produces no alerts. Later batches interleave
    // recognized event types whose provider is unsupported with valid detections.
    let mut records = Vec::new();
    for sequence in 1..=36 {
        records.push(account_event(host, runtime, sequence, false));
    }
    for sequence in 37..=176 {
        records.push(account_event(host, runtime, sequence, sequence % 2 == 0));
    }
    for batch in records.chunks(32) {
        writer.append_batch(batch)?;
    }
    let before = writer.verify_integrity()?;
    let db = Connection::open(fixture.database())?;
    let expected = annotations(&db)?;
    assert_eq!(expected.len(), 70);
    db.execute("DELETE FROM detections", [])?;
    drop(writer);
    for _ in 0..2 {
        let reopened = SqliteEventStore::open(fixture.database(), config.clone())?;
        assert_eq!(reopened.count()?, records.len() as u64);
        assert_eq!(reopened.verify_integrity()?, before);
        assert_eq!(annotations(&db)?, expected);
    }
    Ok(())
}

#[test]
fn backfill_crosses_byte_limit_before_row_limit() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let config = StorageConfig::default();
    let mut writer = SqliteEventStore::open(fixture.database(), config.clone())?;
    let host = writer.host_id();
    let runtime = Uuid::new_v4();
    let records: Vec<_> = (1..=32)
        .map(|sequence| {
            let mut event = account_event(host, runtime, sequence, true);
            event.logon_session = Some("x".repeat(180 * 1024));
            event
        })
        .collect();
    let source_bytes = records.iter().try_fold(0_usize, |total, event| {
        serde_json::to_vec(event).map(|bytes| total + bytes.len())
    })?;
    assert!(source_bytes > 4 * 1024 * 1024);
    for batch in records.chunks(8) {
        writer.append_batch(batch)?;
    }
    let before = writer.verify_integrity()?;
    let db = Connection::open(fixture.database())?;
    let expected = annotations(&db)?;
    assert_eq!(expected.len(), 32);
    db.execute("DELETE FROM detections", [])?;
    drop(writer);

    let reopened = SqliteEventStore::open(fixture.database(), config)?;
    assert_eq!(reopened.count()?, 32);
    assert_eq!(reopened.verify_integrity()?, before);
    assert_eq!(annotations(&db)?, expected);
    Ok(())
}

#[test]
fn first_backfill_batch_is_atomic_when_pinned_wal_exhausts_admission() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let config = StorageConfig {
        max_disk_bytes: 8 * 1024 * 1024,
        ..Default::default()
    };
    let mut writer = SqliteEventStore::open(fixture.database(), config.clone())?;
    let host = writer.host_id();
    let runtime = Uuid::new_v4();
    let records: Vec<_> = (1..=40)
        .map(|sequence| account_event(host, runtime, sequence, true))
        .collect();
    writer.append_batch(&records)?;
    let db = Connection::open(fixture.database())?;
    let expected = annotations(&db)?;
    assert_eq!(expected.len(), 40);
    db.execute("DELETE FROM detections", [])?;

    let reader = Connection::open_with_flags(fixture.database(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snapshot = reader.unchecked_transaction()?;
    assert_eq!(
        snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, u64>(0))?,
        40
    );
    let mut reached_budget = false;
    for sequence in 41..=2000 {
        let event = SecurityEvent::heartbeat(host, runtime, sequence, 100, sequence);
        match writer.append_batch(&[event]) {
            Ok(()) => {}
            Err(StorageError::DiskBudgetExceeded) => {
                reached_budget = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(reached_budget, "fixture must exhaust append admission");
    assert!(writer.archive_bytes()?.1 <= config.max_disk_bytes);
    let before = writer.verify_integrity()?;
    assert!(annotations(&db)?.is_empty());
    assert!(matches!(
        SqliteEventStore::open(fixture.database(), config.clone()),
        Err(StorageError::DiskBudgetExceeded)
    ));
    assert!(
        annotations(&db)?.is_empty(),
        "no partial first annotation batch"
    );
    assert_eq!(writer.verify_integrity()?, before);
    assert!(writer.archive_bytes()?.1 <= config.max_disk_bytes);
    assert_eq!(
        snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, u64>(0))?,
        40,
        "the reader must retain its original snapshot"
    );

    snapshot.rollback()?;
    drop(reader);
    // Test-only maintenance: verify completion, rather than treating successful
    // PRAGMA execution as proof that the checkpoint was not blocked.
    let (busy, frames, checkpointed): (u64, i64, i64) =
        db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    assert_eq!((busy, frames, checkpointed), (0, 0, 0));
    let reopened = SqliteEventStore::open(fixture.database(), config.clone())?;
    assert_eq!(reopened.verify_integrity()?, before);
    assert_eq!(reopened.count()?, before.verified_events);
    assert_eq!(annotations(&db)?, expected);
    assert!(reopened.archive_bytes()?.1 <= config.max_disk_bytes);
    Ok(())
}
