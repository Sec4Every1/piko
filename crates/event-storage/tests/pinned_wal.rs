use std::{error::Error, fs, path::PathBuf};

use piko_event_schema::SecurityEvent;
use piko_event_storage::{SqliteEventStore, StorageConfig, StorageError};
use rusqlite::{Connection, OpenFlags};
use uuid::Uuid;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pinned_reader_refuses_at_budget_then_checkpoint_restores_admission() -> Result<(), Box<dyn Error>>
{
    const BUDGET: u64 = 8 * 1024 * 1024;
    let fixture = Fixture(std::env::temp_dir().join(format!("piko-pinned-wal-{}", Uuid::new_v4())));
    fs::create_dir(&fixture.0)?;
    let path = fixture.0.join("events.db");
    let mut store = SqliteEventStore::open(
        &path,
        StorageConfig {
            max_disk_bytes: BUDGET,
            ..StorageConfig::default()
        },
    )?;
    let runtime = Uuid::new_v4();
    let host = store.host_id();
    store.append_batch(&[SecurityEvent::heartbeat(host, runtime, 1, 100, 1)])?;

    // A SELECT inside a real transaction holds a WAL snapshot across commits.
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snapshot = reader.unchecked_transaction()?;
    assert_eq!(
        snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, u64>(0))?,
        1
    );
    let mut accepted = 1_u64;
    let mut refused = None;
    let mut peak_bytes = store.archive_bytes()?.1;
    for sequence in 2..=2000 {
        let event = SecurityEvent::heartbeat(host, runtime, sequence, 100, sequence);
        match store.append_batch(std::slice::from_ref(&event)) {
            Ok(()) => accepted += 1,
            Err(StorageError::DiskBudgetExceeded) => refused = Some(event),
            Err(error) => return Err(error.into()),
        }
        peak_bytes = peak_bytes.max(store.archive_bytes()?.1);
        assert!(peak_bytes <= BUDGET, "observed aggregate exceeded budget");
        if refused.is_some() {
            break;
        }
    }
    let refused = refused.ok_or("bounded fixture did not reach budget refusal")?;
    let wal_bytes = fs::metadata(fixture.0.join("events.db-wal"))?.len();
    assert!(
        wal_bytes > 1024 * 1024,
        "journal_size_limit is a soft limit"
    );
    assert!(store.active_database_bytes()? < store.database_limit_bytes()?);
    assert_eq!(store.count()?, accepted);
    let before = store.verify_integrity()?;
    assert_eq!(before.verified_events, accepted);
    assert_eq!(
        snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, u64>(0))?,
        1,
        "reader must still hold its original snapshot"
    );

    snapshot.rollback()?;
    drop(reader);
    let maintenance = Connection::open(&path)?;
    let (busy, _, _): (u64, i64, i64) =
        maintenance.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    assert_eq!(busy, 0);
    assert_eq!(fs::metadata(fixture.0.join("events.db-wal"))?.len(), 0);
    assert_eq!(store.verify_integrity()?, before);
    store.append_batch(&[refused])?;
    assert_eq!(store.count()?, accepted + 1);
    assert_eq!(store.verify_integrity()?.verified_events, accepted + 1);
    assert!(store.archive_bytes()?.1 <= BUDGET);
    eprintln!(
        "pinned WAL: accepted={accepted}, peak={peak_bytes}, wal={wal_bytes}, budget={BUDGET}"
    );
    Ok(())
}
