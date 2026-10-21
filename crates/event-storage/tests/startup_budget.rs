use piko_event_schema::SecurityEvent;
use piko_event_storage::{SqliteEventStore, StorageConfig, StorageError};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory =
            std::env::temp_dir().join(format!("piko-startup-budget-{}", Uuid::new_v4()));
        fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn digest(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(Sha256::digest(fs::read(path)?).to_vec())
}

#[test]
fn missing_startup_index_is_refused_before_mutation_near_budget() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let path = fixture.0.join("events.db");
    let wal = fixture.0.join("events.db-wal");
    let config = StorageConfig {
        max_disk_bytes: 8 * 1024 * 1024,
        ..Default::default()
    };
    let mut writer = SqliteEventStore::open(&path, config.clone())?;
    let host = writer.host_id();
    let runtime = Uuid::new_v4();
    writer.append_batch(&[SecurityEvent::heartbeat(host, runtime, 1, 100, 1)])?;
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snapshot = reader.unchecked_transaction()?;
    let _: u64 = snapshot.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    let mut reached = false;
    for sequence in 2..=2000 {
        writer.append_batch(&[SecurityEvent::heartbeat(
            host, runtime, sequence, 100, sequence,
        )])?;
        if writer.archive_bytes()?.1 >= config.max_disk_bytes * 3 / 4 {
            reached = true;
            break;
        }
    }
    assert!(reached, "fixture must reach the migration headroom gate");
    let before = writer.verify_integrity()?;
    // Complete schema can reopen here: do not impose migration reserve on no-op startup.
    let unchanged = SqliteEventStore::open(&path, config.clone())?;
    assert_eq!(unchanged.verify_integrity()?, before);
    drop(unchanged);
    let maintenance = Connection::open(&path)?;
    maintenance.execute("DROP INDEX events_sensor_position", [])?;
    let before_db = digest(&path)?;
    let before_wal = digest(&wal)?;
    assert!(matches!(
        SqliteEventStore::open(&path, config.clone()),
        Err(StorageError::DiskBudgetExceeded)
    ));
    assert_eq!(digest(&path)?, before_db);
    assert_eq!(digest(&wal)?, before_wal);
    let still_missing: bool = maintenance.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='events_sensor_position')",
        [],
        |r| r.get(0),
    )?;
    assert!(still_missing);
    assert_eq!(writer.verify_integrity()?, before);

    snapshot.rollback()?;
    drop(reader);
    let busy: u64 = maintenance.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    assert_eq!(busy, 0);
    let migrated = SqliteEventStore::open(&path, config)?;
    assert_eq!(migrated.verify_integrity()?, before);
    let now_present: bool = maintenance.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='events_sensor_position')",
        [],
        |r| r.get(0),
    )?;
    assert!(now_present);
    Ok(())
}

#[test]
fn interrupted_empty_initialization_resumes_but_existing_evidence_is_never_reidentified(
) -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    for version_written in [false, true] {
        let path = fixture.0.join(format!("initial-{version_written}.db"));
        let initial = Connection::open(&path)?;
        initial.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")?;
        if version_written {
            initial.execute("INSERT INTO metadata VALUES('storage_version','1')", [])?;
        }
        drop(initial);
        let store = SqliteEventStore::open(&path, StorageConfig::default())?;
        assert_eq!(store.verify_integrity()?.verified_events, 0);
        assert!(!store.host_id().is_nil());
    }
    let path = fixture.0.join("existing.db");
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    store.append_batch(&[SecurityEvent::heartbeat(
        store.host_id(),
        Uuid::new_v4(),
        1,
        100,
        1,
    )])?;
    let tamper = Connection::open(&path)?;
    tamper.execute("DELETE FROM metadata WHERE key='host_id'", [])?;
    let before_db = digest(&path)?;
    let before_wal = digest(&fixture.0.join("existing.db-wal"))?;
    assert!(SqliteEventStore::open(&path, StorageConfig::default()).is_err());
    assert_eq!(digest(&path)?, before_db);
    assert_eq!(digest(&fixture.0.join("existing.db-wal"))?, before_wal);
    let host_absent: bool = tamper.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM metadata WHERE key='host_id')",
        [],
        |r| r.get(0),
    )?;
    assert!(host_absent);
    Ok(())
}

#[test]
fn non_piko_objects_and_unknown_metadata_never_become_bootstrap_archives(
) -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    for (name, sql) in [
        ("foreign", "CREATE TABLE notes(value TEXT); INSERT INTO notes VALUES('keep')"),
        ("unknown-metadata", "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO metadata VALUES('future_state','keep')"),
    ] {
        let path = fixture.0.join(format!("{name}.db"));
        let connection = Connection::open(&path)?;
        connection.execute_batch(sql)?;
        drop(connection);
        let before = digest(&path)?;
        assert!(SqliteEventStore::open(&path, StorageConfig::default()).is_err());
        assert_eq!(digest(&path)?, before);
    }
    Ok(())
}

#[test]
fn already_over_budget_file_is_never_opened_for_writing() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let path = fixture.0.join("events.db");
    let config = StorageConfig {
        max_disk_bytes: 8 * 1024 * 1024,
        ..Default::default()
    };
    fs::write(&path, vec![0; config.max_disk_bytes as usize + 1])?;
    let before = digest(&path)?;
    assert!(matches!(
        SqliteEventStore::open(&path, config),
        Err(StorageError::DiskBudgetExceeded)
    ));
    assert_eq!(digest(&path)?, before);
    assert!(!fixture.0.join("events.db-wal").exists());
    assert!(!fixture.0.join("events.db-shm").exists());
    Ok(())
}
