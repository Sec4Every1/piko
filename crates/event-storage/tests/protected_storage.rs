//! Production storage boundaries with an intentionally noncryptographic adapter.
//! These fixtures qualify neither DPAPI/age nor Windows runtime protection.
use piko_event_schema::{EventRecord, RawEvidence, SecurityEvent};
use piko_event_storage::{EvidenceProtection, SqliteEventStore, StorageConfig, StorageError};
use rusqlite::Connection;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;

struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("piko-protected-fixture-{}", Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn database(&self) -> PathBuf {
        self.0.join("events.db")
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct FakeProvider {
    scheme: &'static str,
    key: u8,
    ready: AtomicBool,
    fail_write: AtomicBool,
}

impl FakeProvider {
    fn new(scheme: &'static str, key: u8) -> Arc<Self> {
        Arc::new(Self {
            scheme,
            key,
            ready: AtomicBool::new(true),
            fail_write: AtomicBool::new(false),
        })
    }
}

impl EvidenceProtection for FakeProvider {
    fn scheme(&self) -> &'static str {
        self.scheme
    }

    fn key_identity(&self) -> Option<String> {
        (self.scheme == "age-x25519-v1").then(|| format!("fixture-key-{}", self.key))
    }

    fn validate_new_writes(&self) -> io::Result<()> {
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(io::Error::other("fixture prerequisites unavailable"))
        }
    }

    fn protect(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected fixture write failure"));
        }
        // Key tag and XOR are solely deterministic fault injection, not encryption.
        let mut result = vec![self.key];
        result.extend(bytes.iter().map(|byte| byte ^ self.key));
        Ok(result)
    }

    fn unprotect(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if bytes.first() != Some(&self.key) {
            return Err(io::Error::other("fixture key mismatch"));
        }
        Ok(bytes[1..].iter().map(|byte| byte ^ self.key).collect())
    }
}

fn config(provider: Arc<FakeProvider>, writer: bool) -> StorageConfig {
    StorageConfig {
        protect_new_evidence: writer,
        evidence_protection: Some(provider),
        ..Default::default()
    }
}

fn record(store: &SqliteEventStore, sequence: u64) -> EventRecord {
    let raw = RawEvidence {
        evidence_id: Uuid::new_v4(),
        source: "fixture".into(),
        content_type: "application/octet-stream".into(),
        observed_at_unix_ms: 100,
        bytes: b"synthetic evidence only".to_vec(),
    };
    let mut event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), sequence, 100, 1);
    event.raw_evidence_reference = Some(raw.evidence_id);
    EventRecord {
        event,
        raw_evidence: Some(raw),
    }
}

#[test]
fn both_envelope_versions_roundtrip_through_real_store_and_integrity() -> TestResult {
    for (scheme, magic) in [
        ("dpapi-user-v1", b"PIKOENC\x01"),
        ("age-x25519-v1", b"PIKOENC\x02"),
    ] {
        let directory = Directory::new()?;
        let provider = FakeProvider::new(scheme, 71);
        let mut store =
            SqliteEventStore::open(directory.database(), config(provider.clone(), true))?;
        let record = record(&store, 1);
        let raw = record
            .raw_evidence
            .as_ref()
            .ok_or("missing fixture")?
            .clone();
        store.append_records(&[record])?;
        assert_eq!(
            store
                .raw_evidence(raw.evidence_id)?
                .ok_or("missing raw")?
                .bytes,
            raw.bytes
        );
        assert_eq!(store.verify_integrity()?.verified_events, 1);
        drop(store);
        let connection = Connection::open(directory.database())?;
        let payload: Vec<u8> =
            connection.query_row("SELECT payload FROM raw_evidence", [], |row| row.get(0))?;
        assert!(payload.starts_with(magic));
        drop(connection);
        let reopened = SqliteEventStore::open(directory.database(), config(provider, true))?;
        assert_eq!(reopened.verify_integrity()?.verified_events, 1);
        assert_eq!(
            reopened
                .raw_evidence(raw.evidence_id)?
                .ok_or("missing reopened raw")?
                .bytes,
            raw.bytes
        );
    }
    Ok(())
}

#[test]
fn marked_archive_refuses_missing_disabled_wrong_key_and_wrong_scheme_writers() -> TestResult {
    for scheme in ["dpapi-user-v1", "age-x25519-v1"] {
        let directory = Directory::new()?;
        let provider = FakeProvider::new(scheme, 71);
        let mut store =
            SqliteEventStore::open(directory.database(), config(provider.clone(), true))?;
        store.append_records(&[record(&store, 1)])?;
        drop(store);
        let other_scheme = if scheme == "dpapi-user-v1" {
            "age-x25519-v1"
        } else {
            "dpapi-user-v1"
        };
        for denied in [
            StorageConfig::default(),
            config(provider.clone(), false),
            config(FakeProvider::new(scheme, 72), true),
            config(FakeProvider::new(other_scheme, 71), true),
        ] {
            assert!(matches!(
                SqliteEventStore::open(directory.database(), denied),
                Err(StorageError::ProtectionPolicy(_))
            ));
        }
        assert_eq!(
            SqliteEventStore::open(directory.database(), config(provider, true))?
                .verify_integrity()?
                .verified_events,
            1
        );
    }
    Ok(())
}

#[test]
fn protected_reader_can_read_but_cannot_copy_or_run_writer_maintenance() -> TestResult {
    let directory = Directory::new()?;
    let provider = FakeProvider::new("age-x25519-v1", 71);
    let mut writer = SqliteEventStore::open(directory.database(), config(provider.clone(), true))?;
    let item = record(&writer, 1);
    let id = item
        .event
        .raw_evidence_reference
        .ok_or("missing reference")?;
    writer.append_records(&[item])?;
    drop(writer);
    let mut reader = SqliteEventStore::reader(directory.database(), config(provider, false))?;
    assert!(reader.raw_evidence(id)?.is_some());
    assert_eq!(reader.verify_integrity()?.verified_events, 1);
    let destination = directory.0.join("copy.db");
    assert!(matches!(
        reader.copy_without_noise(&destination),
        Err(StorageError::ProtectionPolicy(_))
    ));
    assert!(!destination.exists());
    assert!(matches!(
        reader.maintain_archive_batch(0),
        Err(StorageError::ProtectionPolicy(_))
    ));
    Ok(())
}

#[test]
fn provider_write_failure_preserves_prior_records_without_plaintext_fallback() -> TestResult {
    let directory = Directory::new()?;
    let provider = FakeProvider::new("age-x25519-v1", 71);
    let mut store = SqliteEventStore::open(directory.database(), config(provider.clone(), true))?;
    let first = record(&store, 1);
    let first_id = first
        .event
        .raw_evidence_reference
        .ok_or("missing reference")?;
    store.append_records(&[first])?;
    let before = store.verify_integrity()?;
    let refused = record(&store, 2);
    let refused_id = refused
        .event
        .raw_evidence_reference
        .ok_or("missing reference")?;
    provider.fail_write.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.append_records(&[refused]),
        Err(StorageError::ProtectionPolicy(_))
    ));
    assert_eq!(store.verify_integrity()?, before);
    assert!(store.raw_evidence(first_id)?.is_some());
    assert!(store.raw_evidence(refused_id)?.is_none());
    let connection = Connection::open(directory.database())?;
    let count: u64 =
        connection.query_row("SELECT COUNT(*) FROM raw_evidence", [], |row| row.get(0))?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn missing_policy_marker_refuses_downgrade_and_implicit_reactivation() -> TestResult {
    for retain_probe in [true, false] {
        let directory = Directory::new()?;
        let provider = FakeProvider::new("age-x25519-v1", 71);
        let mut store =
            SqliteEventStore::open(directory.database(), config(provider.clone(), true))?;
        store.append_records(&[record(&store, 1)])?;
        drop(store);
        let connection = Connection::open(directory.database())?;
        connection.execute(
            "DELETE FROM metadata WHERE key='raw_evidence_protection'",
            [],
        )?;
        if !retain_probe {
            connection.execute("DELETE FROM metadata WHERE key IN ('raw_evidence_key_probe','raw_evidence_key_id')", [])?;
        }
        drop(connection);
        assert!(matches!(
            SqliteEventStore::open(directory.database(), StorageConfig::default()),
            Err(StorageError::ProtectionPolicy(_))
        ));
        // Even the original key must not reconstruct missing policy metadata
        // implicitly. Recovery belongs to an explicit reviewed workflow.
        assert!(matches!(
            SqliteEventStore::open(directory.database(), config(provider, true)),
            Err(StorageError::ProtectionPolicy(_))
        ));
        let connection = Connection::open(directory.database())?;
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM metadata WHERE key='raw_evidence_protection'",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            0
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM raw_evidence", [], |row| row
                .get::<_, u64>(0))?,
            1
        );
    }
    Ok(())
}

#[test]
fn tampered_protected_rows_never_return_evidence_or_valid_integrity() -> TestResult {
    for scheme in ["dpapi-user-v1", "age-x25519-v1"] {
        let directory = Directory::new()?;
        let mut store = SqliteEventStore::open(
            directory.database(),
            config(FakeProvider::new(scheme, 71), true),
        )?;
        let item = record(&store, 1);
        let id = item
            .event
            .raw_evidence_reference
            .ok_or("missing reference")?;
        store.append_records(&[item])?;
        let verified = store.verify_integrity()?;
        let connection = Connection::open(directory.database())?;
        let original: Vec<u8> =
            connection.query_row("SELECT payload FROM raw_evidence", [], |row| row.get(0))?;
        for fault in 0..4 {
            let mut damaged = original.clone();
            match fault {
                0 => damaged.truncate(12),
                1 => damaged[7] = 99,
                2 => damaged[8..12].copy_from_slice(&0_u32.to_le_bytes()),
                _ => *damaged.last_mut().ok_or("empty envelope")? ^= 0x40,
            }
            connection.execute("UPDATE raw_evidence SET payload=?1", [damaged])?;
            assert!(store.raw_evidence(id).is_err());
            assert!(store.verify_integrity().is_err());
            connection.execute("UPDATE raw_evidence SET payload=?1", [&original])?;
            assert!(store.raw_evidence(id)?.is_some());
            assert_eq!(store.verify_integrity()?, verified);
        }
    }
    Ok(())
}

#[test]
fn unavailable_preconditions_and_missing_provider_refuse_before_archive_creation() -> TestResult {
    let directory = Directory::new()?;
    let provider = FakeProvider::new("age-x25519-v1", 71);
    provider.ready.store(false, Ordering::SeqCst);
    assert!(matches!(
        SqliteEventStore::open(directory.database(), config(provider, true)),
        Err(StorageError::ProtectionPolicy(_))
    ));
    assert!(!directory.database().exists());
    let missing_provider = StorageConfig {
        protect_new_evidence: true,
        ..Default::default()
    };
    assert!(matches!(
        SqliteEventStore::open(directory.database(), missing_provider),
        Err(StorageError::ProtectionPolicy(_))
    ));
    assert!(!directory.database().exists());
    Ok(())
}
