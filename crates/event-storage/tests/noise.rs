use piko_event_schema::{EventRecord, RawEvidence, SecurityEvent, Severity};
use piko_event_storage::{EventQuery, SqliteEventStore, StorageConfig};
use rusqlite::{params, Connection};
use uuid::Uuid;

#[test]
fn noise_copy_preserves_security_evidence_bookmarks_and_detection_links(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("piko-noise-{}", Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    let source = dir.join("source.db");
    let target = dir.join("target.db");
    let mut store = SqliteEventStore::open(&source, StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    let mut records = Vec::new();
    for (i, kind) in [
        "runtime.heartbeat",
        "image.etw.unloaded",
        "image.etw.loaded",
        "windows.event_log.5157",
        "windows.event_log.1102",
        "image.etw.unloaded",
        "image.etw.unloaded",
    ]
    .iter()
    .enumerate()
    {
        let mut e = SecurityEvent::heartbeat(store.host_id(), runtime, i as u64 + 1, 1000, 1);
        e.event_type = (*kind).into();
        e.result = "observed".into();
        e.sensor_id = if kind.starts_with("image") {
            "windows.etw.process_image"
        } else if kind.starts_with("windows") {
            "windows.event_log.Security"
        } else {
            "piko.runtime"
        }
        .into();
        if kind.starts_with("windows") {
            e.integrity_metadata.source_integrity = Some("durable-source-bookmark".into());
        }
        if i == 5 {
            e.severity = Severity::High;
        } // Unusual or malformed telemetry is retained.
        let raw = RawEvidence {
            evidence_id: Uuid::new_v4(),
            source: e.sensor_id.clone(),
            content_type: "application/xml".into(),
            observed_at_unix_ms: 1000,
            bytes: b"<Event>security evidence unchanged</Event>".to_vec(),
        };
        e.raw_evidence_reference = Some(raw.evidence_id);
        records.push(EventRecord {
            event: e,
            raw_evidence: Some(raw),
        });
    }
    store.append_records(&records)?;
    let original = store.verify_integrity()?;
    let conn = Connection::open(&source)?;
    // A detection attached to a normally removable type must keep that event.
    conn.execute(
        "INSERT INTO detections(id,event_id,payload) VALUES('future-rule',?1,?2)",
        params![records[1].event.event_id.to_string(), b"{}".as_slice()],
    )?;
    let report = store.copy_without_noise(&target)?;
    assert_eq!(report.before, original);
    assert_eq!(report.after.verified_events, 5);
    assert_eq!(report.removed.get("runtime.heartbeat"), Some(&1));
    assert_eq!(report.removed.get("image.etw.unloaded"), Some(&1));
    let copied = SqliteEventStore::reader(&target, StorageConfig::default())?;
    assert_eq!(
        copied.latest_sensor_event("windows.event_log.Security")?,
        Some(records[4].event.clone())
    );
    let events = copied.query(&EventQuery {
        limit: 20,
        ..Default::default()
    })?;
    for record in &records[1..6] {
        assert!(events.contains(&record.event));
        assert_eq!(
            copied.raw_evidence(record.raw_evidence.as_ref().unwrap().evidence_id)?,
            record.raw_evidence
        );
    }
    assert!(!events.contains(&records[6].event));
    assert!(copied
        .raw_evidence(records[6].raw_evidence.as_ref().unwrap().evidence_id)?
        .is_none());
    assert_eq!(store.verify_integrity()?, original); // Source chain never changed.
    assert!(store.copy_without_noise(&target).is_err()); // Existing output is never overwritten.
    conn.execute("UPDATE detections SET payload=zeroblob(4194305)", [])?;
    let oversized_target = dir.join("oversized-copy.db");
    assert!(store.copy_without_noise(&oversized_target).is_err());
    assert_eq!(store.verify_integrity()?, original);
    let retained_size: u64 = conn.query_row(
        "SELECT length(payload) FROM detections WHERE id='future-rule'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(retained_size, 4_194_305);
    conn.execute("UPDATE events SET hash=zeroblob(32) WHERE position=2", [])?;
    assert!(store
        .copy_without_noise(&dir.join("corrupt-copy.db"))
        .is_err());
    assert!(!dir.join("corrupt-copy.db").exists());
    Ok(())
}
