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
    exercise_pinned_reader(8 * 1024 * 1024, true)
}

#[test]
fn large_wal_stays_explicitly_refused_until_maintenance() -> Result<(), Box<dyn Error>> {
    exercise_pinned_reader(32 * 1024 * 1024, false)
}

fn exercise_pinned_reader(budget: u64, automatic: bool) -> Result<(), Box<dyn Error>> {
    let fixture = Fixture(std::env::temp_dir().join(format!("piko-pinned-wal-{}", Uuid::new_v4())));
    fs::create_dir(&fixture.0)?;
    let path = fixture.0.join("events.db");
    let mut store = SqliteEventStore::open(
        &path,
        StorageConfig {
            max_disk_bytes: budget,
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
        assert!(peak_bytes <= budget, "observed aggregate exceeded budget");
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
    // A no-op expiry is allowed at capacity; an actual deletion needs headroom.
    assert_eq!(store.expire_before(100)?, 0);
    assert!(matches!(
        store.expire_before(101),
        Err(StorageError::DiskBudgetExceeded)
    ));
    assert_eq!(store.verify_integrity()?, before);
    assert_eq!(store.expired_events()?, 0);
    let inspector = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let logical_pages: u64 = inspector.pragma_query_value(None, "page_count", |r| r.get(0))?;
    let page_size: u64 = inspector.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let (main_bytes, aggregate) = store.archive_bytes()?;
    let projected_checkpoint_peak =
        aggregate + (logical_pages * page_size).saturating_sub(main_bytes);
    assert!(
        projected_checkpoint_peak <= budget,
        "checkpoint must fit before WAL truncation"
    );
    drop(inspector);
    for _ in 0..2 {
        assert!(matches!(
            store.append_batch(std::slice::from_ref(&refused)),
            Err(StorageError::DiskBudgetExceeded)
        ));
        assert_eq!(store.verify_integrity()?, before);
        assert!(store.archive_bytes()?.1 <= budget);
    }
    assert_eq!(
        snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, u64>(0))?,
        1,
        "reader must still hold its original snapshot"
    );

    snapshot.rollback()?;
    drop(reader);
    assert_eq!(store.verify_integrity()?, before);
    if !automatic {
        assert!(wal_bytes > 16 * 1024 * 1024);
        assert!(matches!(
            store.append_batch(std::slice::from_ref(&refused)),
            Err(StorageError::DiskBudgetExceeded)
        ));
        assert_eq!(store.verify_integrity()?, before);
        assert_eq!(
            fs::metadata(fixture.0.join("events.db-wal"))?.len(),
            wal_bytes
        );
        let maintenance = Connection::open(&path)?;
        let busy: u64 =
            maintenance.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        assert_eq!(busy, 0);
    }
    // Small WALs need no external maintenance after the reader releases.
    store.append_batch(&[refused])?;
    assert!(fs::metadata(fixture.0.join("events.db-wal"))?.len() < wal_bytes);
    assert_eq!(store.count()?, accepted + 1);
    assert_eq!(store.verify_integrity()?.verified_events, accepted + 1);
    assert!(store.archive_bytes()?.1 <= budget);
    eprintln!(
        "pinned WAL: accepted={accepted}, peak={peak_bytes}, wal={wal_bytes}, checkpoint_peak_bound={projected_checkpoint_peak}, budget={budget}, automatic={automatic}"
    );
    Ok(())
}
