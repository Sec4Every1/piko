use piko_event_schema::{EventRecord, RawEvidence, SecurityEvent};
use piko_event_storage::{calendar_cutoff, SqliteEventStore, StorageConfig};
use rusqlite::Connection;
use uuid::Uuid;
fn stamp(year: i32, month: time::Month, day: u8) -> i64 {
    time::Date::from_calendar_date(year, month, day)
        .unwrap()
        .with_hms(12, 0, 0)
        .unwrap()
        .assume_utc()
        .unix_timestamp()
        * 1000
}

#[test]
fn calendar_months_clamp_leap_days_and_preserve_time() {
    assert_eq!(
        calendar_cutoff(stamp(2024, time::Month::February, 29), 12).unwrap(),
        stamp(2023, time::Month::February, 28)
    );
    assert_eq!(
        calendar_cutoff(stamp(2024, time::Month::March, 31), 1).unwrap(),
        stamp(2024, time::Month::February, 29)
    );
    assert!(calendar_cutoff(0, 0).is_err());
    assert!(calendar_cutoff(0, 121).is_err());
}

#[test]
fn expiry_keeps_recent_records_bookmarks_and_sequence_after_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("piko-retention-{}.db", Uuid::new_v4()));
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    let host = store.host_id();
    let now = stamp(2026, time::Month::October, 14);
    let cutoff = calendar_cutoff(now, 12)?;
    let mut retired_id = Uuid::nil();
    for sequence in 1..=4 {
        let mut event = SecurityEvent::heartbeat(host, runtime, sequence, now, 1);
        event.ingestion_time = if sequence == 3 { cutoff } else { cutoff - 1 };
        if sequence != 3 {
            event.sensor_id = "windows.event_log.System".into();
            event.integrity_metadata.source_integrity = Some(format!("bookmark-{sequence}"));
        }
        let raw = RawEvidence {
            evidence_id: Uuid::new_v4(),
            source: event.sensor_id.clone(),
            content_type: "application/xml; charset=utf-8".into(),
            observed_at_unix_ms: now,
            bytes: b"<Data>benign repeated fixture</Data>".repeat(100),
        };
        if sequence == 1 {
            retired_id = raw.evidence_id;
        }
        event.raw_evidence_reference = Some(raw.evidence_id);
        store.append_records(&[EventRecord {
            event,
            raw_evidence: Some(raw),
        }])?;
    }
    assert_eq!(store.expire_before(cutoff)?, 2);
    // A recent prefix boundary protects everything after it, including clock rollback.
    assert_eq!(store.expire_before(cutoff)?, 0);
    assert_eq!(store.count()?, 2);
    assert!(store.raw_evidence(retired_id)?.is_none());
    let verified = store.verify_integrity()?;
    assert_eq!((verified.verified_events, verified.expired_events), (2, 2));
    drop(store);
    let reader = SqliteEventStore::reader(&path, StorageConfig::default())?;
    assert_eq!(reader.verify_integrity()?.expired_events, 2);
    drop(reader);
    store = SqliteEventStore::open(&path, StorageConfig::default())?;
    let mut replay = SecurityEvent::heartbeat(host, runtime, 1, now, 1);
    replay.sensor_id = "windows.event_log.System".into();
    assert!(store.append_batch(&[replay]).is_err());
    assert_eq!(store.expire_before(now + 1)?, 2);
    assert_eq!(store.count()?, 0);
    assert_eq!(
        store
            .latest_sensor_event("windows.event_log.System")?
            .unwrap()
            .integrity_metadata
            .source_integrity
            .as_deref(),
        Some("bookmark-4")
    );
    let mut next = SecurityEvent::heartbeat(host, runtime, 5, now + 2, 1);
    next.sensor_id = "windows.event_log.System".into();
    store.append_batch(&[next])?;
    assert_eq!(
        (
            store.verify_integrity()?.verified_events,
            store.verify_integrity()?.expired_events
        ),
        (1, 4)
    );
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE metadata SET value='{}' WHERE key='retention_checkpoint'",
        [],
    )?;
    assert!(store.verify_integrity().is_err());
    Ok(())
}

#[test]
fn corruption_never_becomes_an_authorized_expiry() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("piko-expiry-corrupt-{}.db", Uuid::new_v4()));
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    let event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), 1, 100, 1);
    store.append_batch(&[event])?;
    let connection = Connection::open(&path)?;
    connection.execute("UPDATE events SET hash=zeroblob(32)", [])?;
    assert!(store.expire_before(1000).is_err());
    assert_eq!(store.count()?, 1);
    Ok(())
}
