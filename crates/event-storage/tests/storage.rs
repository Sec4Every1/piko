use std::error::Error;
use std::fs;
use std::path::PathBuf;

use piko_event_schema::{EventRecord, RawEvidence, SecurityEvent, Severity};
use piko_event_storage::{EventQuery, SqliteEventStore, StorageConfig, StorageError};
use rusqlite::Connection;
use uuid::Uuid;

struct TestDirectory(PathBuf);

#[test]
fn structured_queries_filter_before_limit_and_keep_missing_data_unknown(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    let mut first = SecurityEvent::heartbeat(store.host_id(), runtime, 1, 100, 1);
    if let Some(process) = &mut first.process {
        process.name = Some("example.exe".into());
        process.pid = 42;
    }
    let mut second = SecurityEvent::heartbeat(store.host_id(), runtime, 2, 200, 2);
    second.process = None;
    store.append_batch(&[first.clone(), second.clone()])?;
    let query = |expression: &str| EventQuery {
        limit: 1,
        expression: Some(expression.into()),
        ..EventQuery::default()
    };
    assert_eq!(
        store.query(&query(
            r#"process.name = "example.exe" AND process.pid >= 42"#
        ))?[0]
            .event_id,
        first.event_id
    );
    assert!(store
        .query(&query(r#"process.name != "example.exe""#))?
        .is_empty());
    assert_eq!(
        store.query(&query("process.name = null"))?[0].event_id,
        second.event_id
    );
    assert!(store
        .query(&query(r#"process.name = "x' OR 1=1 --""#))?
        .is_empty());
    assert_eq!(
        store.query(&query(r#"process.name CONTAINS "EXAMPLE""#))?[0].event_id,
        first.event_id
    );
    assert_eq!(
        store.query(&query(
            r#"process.pid = 42 OR process.name = null AND event.time > 300"#
        ))?[0]
            .event_id,
        first.event_id
    );
    assert!(matches!(
        store.query(&query("network.destination.first_seen = true")),
        Err(StorageError::QuerySyntax(_))
    ));
    assert_eq!(store.verify_integrity()?.verified_events, 2);
    Ok(())
}

#[test]
fn alert_names_and_scores_rebuild_from_evidence_after_upgrade() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let mut event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), 1, 100, 1);
    event.sensor_id = "windows.event_log.System".into();
    event.event_category = "windows_event_log".into();
    event.event_type = "windows.event_log.7045".into();
    event.target = Some(piko_event_schema::EventTarget {
        kind: "windows_event_record".into(),
        identifier: "System:Service Control Manager:123".into(),
    });
    let raw = RawEvidence {
        evidence_id: Uuid::new_v4(),
        source: event.sensor_id.clone(),
        content_type: "application/xml; charset=utf-8".into(),
        observed_at_unix_ms: event.observation_time,
        bytes: br#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><Version>0</Version><EventRecordID>123</EventRecordID><Channel>System</Channel></System><EventData><Data Name="ServiceName">Example Backup</Data><Data Name="ImagePath">C:\Users\Example\backup.exe</Data><Data Name="AccountName">LocalSystem</Data></EventData></Event>"#.to_vec(),
    };
    event.raw_evidence_reference = Some(raw.evidence_id);
    store.append_records(&[EventRecord {
        event: event.clone(),
        raw_evidence: Some(raw),
    }])?;
    let verify_assessment = |store: &SqliteEventStore| -> Result<(), Box<dyn Error>> {
        let alerts = store.alerts()?;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_id, event.event_id);
        let result = alerts[0].assessment.as_ref().ok_or("missing assessment")?;
        assert_eq!(result.model_version, "piko-risk-v1");
        assert_eq!(result.risk_score, 45);
        assert_eq!(result.false_positive_probability, None);
        assert_eq!(result.context.evidence_status, "verified");
        assert_eq!(
            result.context.service_name.as_deref(),
            Some("Example Backup")
        );
        assert_eq!(result.context.installer_process, None);
        Ok(())
    };
    verify_assessment(&store)?;
    // The derived detection payload is deliberately not trusted on read.
    let connection = Connection::open(directory.database())?;
    connection.execute("UPDATE detections SET payload=X'010203'", [])?;
    verify_assessment(&store)?;
    drop(store);
    // Simulate upgrading a store from before the derived detection index.
    connection.execute("DELETE FROM detections", [])?;
    drop(connection);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    verify_assessment(&store)?;
    assert_eq!(store.verify_integrity()?.verified_events, 1);
    // Even a live store must refuse names from bytes with a broken digest.
    let connection = Connection::open(directory.database())?;
    connection.execute("UPDATE raw_evidence SET payload=X'010203'", [])?;
    assert!(matches!(store.alerts(), Err(StorageError::Corrupt(_))));
    Ok(())
}

#[test]
fn alerts_expose_unavailable_context_without_inventing_names() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let mut batch = events(store.host_id(), Uuid::new_v4(), 2);
    for event in &mut batch {
        event.sensor_id = "windows.event_log.System".into();
        event.event_category = "windows_event_log".into();
        event.event_type = "windows.event_log.7045".into();
        event.target = Some(piko_event_schema::EventTarget {
            kind: "windows_event_record".into(),
            identifier: "System:Service Control Manager:123".into(),
        });
    }
    let raw = RawEvidence {
        evidence_id: Uuid::new_v4(),
        source: batch[1].sensor_id.clone(),
        content_type: "application/xml; charset=utf-8".into(),
        observed_at_unix_ms: batch[1].observation_time,
        bytes: b"<Unrelated><ServiceName>Misleading Name</ServiceName></Unrelated>".to_vec(),
    };
    batch[1].raw_evidence_reference = Some(raw.evidence_id);
    store.append_records(&[
        EventRecord {
            event: batch[0].clone(),
            raw_evidence: None,
        },
        EventRecord {
            event: batch[1].clone(),
            raw_evidence: Some(raw),
        },
    ])?;
    let alerts = store.alerts()?;
    assert_eq!(alerts.len(), 2);
    for (alert, status) in alerts.iter().zip(["invalid", "missing"]) {
        let result = alert.assessment.as_ref().ok_or("missing assessment")?;
        assert_eq!(result.context.evidence_status, status);
        assert_eq!(result.context.service_name, None);
        assert_eq!(result.context.image_path, None);
        assert_eq!(result.risk_score, 25);
        assert_eq!(result.false_positive_probability, None);
    }
    assert_eq!(store.verify_integrity()?.verified_events, 2);
    Ok(())
}

#[test]
fn detections_commit_with_evidence_and_rebuild_after_upgrade() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let mut batch = events(store.host_id(), Uuid::new_v4(), 3);
    for event in &mut batch {
        event.sensor_id = "windows.event_log.System".into();
        event.event_category = "windows_event_log".into();
        event.event_type = "windows.event_log.7045".into();
        event.target = Some(piko_event_schema::EventTarget {
            kind: "windows_event_record".into(),
            identifier: "System:Service Control Manager:123".into(),
        });
    }
    store.append_batch(&batch[..1])?;
    assert_eq!(store.alerts()?.len(), 1);
    let mut invalid = batch[2].clone();
    invalid.event_id = batch[0].event_id;
    assert!(store.append_batch(&[batch[1].clone(), invalid]).is_err());
    assert_eq!(store.alerts()?.len(), 1);
    assert_eq!(store.alerts()?[0].event_id, batch[0].event_id);
    drop(store);
    let connection = Connection::open(directory.database())?;
    connection.execute("DELETE FROM detections", [])?;
    drop(connection);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    assert_eq!(store.alerts()?.len(), 1);
    assert_eq!(store.count()?, 1);
    Ok(())
}

#[test]
fn sensor_bookmark_advances_only_after_a_durable_atomic_commit() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    let mut batch = events(store.host_id(), runtime, 3);
    for (index, event) in batch.iter_mut().enumerate() {
        event.sensor_id = "windows.event_log.System".into();
        event.integrity_metadata.source_integrity = Some(format!("bookmark-{}", index + 1));
    }
    store.append_batch(&batch[..1])?;
    // Duplicate event ID causes the second transaction to roll back, including
    // its otherwise-valid second bookmark.
    let mut invalid = batch[2].clone();
    invalid.event_id = batch[0].event_id;
    assert!(store.append_batch(&[batch[1].clone(), invalid]).is_err());
    drop(store);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let latest = store
        .latest_sensor_event("windows.event_log.System")?
        .ok_or("missing checkpoint")?;
    assert_eq!(
        latest.integrity_metadata.source_integrity.as_deref(),
        Some("bookmark-1")
    );
    assert_eq!(store.count()?, 1);
    Ok(())
}

impl TestDirectory {
    fn new() -> Result<Self, std::io::Error> {
        let path = std::env::temp_dir().join(format!("piko-storage-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
    fn database(&self) -> PathBuf {
        self.0.join("events.sqlite3")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn events(host: Uuid, runtime: Uuid, count: u64) -> Vec<SecurityEvent> {
    (1..=count)
        .map(|sequence| {
            SecurityEvent::heartbeat(
                host,
                runtime,
                sequence,
                10_000 - sequence as i64,
                sequence * 100,
            )
        })
        .collect()
}

#[test]
fn replay_is_atomic_durable_and_uses_sequence_despite_wall_clock_rollback(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let host = store.host_id();
    let mut batch = events(host, Uuid::new_v4(), 3);
    batch[1].event_type = "synthetic.credential_access".into();
    batch[1].severity = Severity::High;
    let causal_parent = batch[1].event_id;
    batch[2].causal_parents.push(causal_parent);
    store.append_batch(&batch)?;
    assert_eq!(store.count()?, 3);
    let report = store.verify_integrity()?;
    assert_eq!(report.verified_events, 3);
    assert!(!report.externally_anchored);
    assert_eq!(report.head_hash.as_ref().map(String::len), Some(64));
    assert_eq!(
        store.query(&EventQuery::default())?,
        batch.iter().rev().cloned().collect::<Vec<_>>()
    );
    // Replaying identical IDs is explicit failure, never duplicate evidence.
    assert!(store.append_batch(&batch).is_err());
    assert_eq!(store.count()?, 3);
    drop(store);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    assert_eq!(store.host_id(), host);
    assert_eq!(store.verify_integrity()?, report);
    let results = store.query(&EventQuery {
        severity: Some(Severity::High),
        search: Some("credential_access".into()),
        ..EventQuery::default()
    })?;
    assert_eq!(results, vec![batch[1].clone()]);
    assert!(store
        .query(&EventQuery {
            limit: 1001,
            ..EventQuery::default()
        })
        .is_err());
    assert!(store
        .query(&EventQuery {
            search: Some("%_'; DROP TABLE events;--".into()),
            ..EventQuery::default()
        })?
        .is_empty());
    assert_eq!(store.count()?, 3);
    Ok(())
}

#[test]
fn any_failure_rolls_back_the_entire_batch() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let mut batch = events(store.host_id(), Uuid::new_v4(), 2);
    batch[1].sequence = 1;
    assert!(matches!(
        store.append_batch(&batch),
        Err(StorageError::SequenceRegression)
    ));
    assert_eq!(store.count()?, 0);
    assert_eq!(store.verify_integrity()?.verified_events, 0);
    Ok(())
}

#[test]
fn process_restart_permits_sequence_reset_without_claiming_windows_reboot(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    for _ in 0..3 {
        let batch = events(store.host_id(), Uuid::new_v4(), 2);
        assert!(batch.iter().all(|event| event.boot_id.is_none()));
        store.append_batch(&batch)?;
    }
    assert_eq!(store.verify_integrity()?.verified_events, 6);
    Ok(())
}

#[test]
fn original_raw_evidence_is_preserved_and_tampering_is_detected() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let path = directory.database();
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    let mut event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), 1, 100, 1);
    let raw = RawEvidence {
        evidence_id: Uuid::new_v4(),
        source: "synthetic.replay".into(),
        content_type: "application/octet-stream".into(),
        observed_at_unix_ms: 100,
        bytes: vec![0, 1, 255, 128, 0],
    };
    event.raw_evidence_reference = Some(raw.evidence_id);
    assert!(matches!(
        store.append_batch(&[event.clone()]),
        Err(StorageError::InvalidRawEvidence)
    ));
    store.append_records(&[EventRecord {
        event,
        raw_evidence: Some(raw.clone()),
    }])?;
    assert_eq!(store.raw_evidence(raw.evidence_id)?, Some(raw));
    assert_eq!(store.verify_integrity()?.verified_events, 1);
    let connection = Connection::open(&path)?;
    connection.execute("UPDATE raw_evidence SET payload=X'010203'", [])?;
    assert!(matches!(
        store.verify_integrity(),
        Err(StorageError::Corrupt(_))
    ));
    drop(connection);
    drop(store);
    assert!(SqliteEventStore::open(&path, StorageConfig::default()).is_err());
    Ok(())
}

#[test]
fn compressed_and_legacy_evidence_share_the_original_digest_and_chain() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new()?;
    let path = directory.database();
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    let mut originals = Vec::new();
    for sequence in 1..=2 {
        let raw = RawEvidence {
            evidence_id: Uuid::new_v4(),
            source: "synthetic.replay".into(),
            content_type: "application/xml; charset=utf-8".into(),
            observed_at_unix_ms: 100,
            bytes: b"<Data>Long repeated benign field</Data>".repeat(4096),
        };
        let mut event = SecurityEvent::heartbeat(store.host_id(), runtime, sequence, 100, 1);
        event.raw_evidence_reference = Some(raw.evidence_id);
        store.append_records(&[EventRecord {
            event,
            raw_evidence: Some(raw.clone()),
        }])?;
        originals.push(raw);
    }
    let head = store.verify_integrity()?.head_hash;
    let connection = Connection::open(&path)?;
    let encoded: Vec<u8> = connection.query_row(
        "SELECT payload FROM raw_evidence WHERE evidence_id=?1",
        [originals[0].evidence_id.to_string()],
        |r| r.get(0),
    )?;
    assert!(encoded.starts_with(b"PIKOEV\x01"));
    let legacy = serde_json::to_vec(&originals[0])?;
    assert!(encoded.len() * 4 < legacy.len());
    // Same logical bytes/digest: representation changes never rewrite the chain.
    connection.execute(
        "UPDATE raw_evidence SET payload=?1 WHERE evidence_id=?2",
        rusqlite::params![legacy, originals[0].evidence_id.to_string()],
    )?;
    assert_eq!(store.verify_integrity()?.head_hash, head);
    for raw in &originals {
        assert_eq!(store.raw_evidence(raw.evidence_id)?, Some(raw.clone()));
    }
    drop(store);
    let reader = SqliteEventStore::reader(&path, StorageConfig::default())?;
    assert_eq!(reader.verify_integrity()?.verified_events, 2);
    drop(reader);
    store = SqliteEventStore::open(&path, StorageConfig::default())?;
    assert_eq!(store.verify_integrity()?.head_hash, head);
    let (cursor, scanned, changed, saved) = store.compress_existing_evidence(0)?;
    assert_eq!((scanned, changed), (2, 1));
    assert!(saved > 0);
    assert_eq!(store.verify_integrity()?.head_hash, head);
    assert_eq!(store.compress_existing_evidence(cursor)?.1, 0);
    assert_eq!(store.compress_existing_evidence(0)?.2, 0);
    let mut damaged = encoded;
    damaged[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
    connection.execute(
        "UPDATE raw_evidence SET payload=?1 WHERE evidence_id=?2",
        rusqlite::params![damaged, originals[1].evidence_id.to_string()],
    )?;
    assert!(store.raw_evidence(originals[1].evidence_id).is_err());
    assert!(store.verify_integrity().is_err());
    Ok(())
}

#[test]
fn interior_deletion_and_index_tampering_are_detected() -> Result<(), Box<dyn Error>> {
    for mutation in [
        "DELETE FROM events WHERE position=2",
        "UPDATE events SET severity='critical' WHERE position=2",
        "UPDATE events SET payload=X'7b7d' WHERE position=2",
    ] {
        let directory = TestDirectory::new()?;
        let path = directory.database();
        let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
        store.append_batch(&events(store.host_id(), Uuid::new_v4(), 3))?;
        let connection = Connection::open(&path)?;
        connection.execute(mutation, [])?;
        assert!(
            store.verify_integrity().is_err(),
            "mutation must be detected: {mutation}"
        );
        drop(connection);
        drop(store);
        assert!(SqliteEventStore::open(&path, StorageConfig::default()).is_err());
    }
    Ok(())
}

#[test]
fn unanchored_chain_explicitly_does_not_detect_tail_truncation() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let path = directory.database();
    let mut store = SqliteEventStore::open(&path, StorageConfig::default())?;
    store.append_batch(&events(store.host_id(), Uuid::new_v4(), 3))?;
    let original_head = store.verify_integrity()?.head_hash;
    let connection = Connection::open(&path)?;
    connection.execute("DELETE FROM events WHERE position=3", [])?;
    let truncated = store.verify_integrity()?;
    assert_eq!(truncated.verified_events, 2);
    assert!(!truncated.externally_anchored);
    assert_ne!(truncated.head_hash, original_head);
    Ok(())
}

#[test]
fn disk_and_event_budgets_refuse_writes_without_losing_existing_evidence(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(
        directory.database(),
        StorageConfig {
            max_disk_bytes: 8 * 1024 * 1024,
            ..StorageConfig::default()
        },
    )?;
    let runtime = Uuid::new_v4();
    store.append_batch(&events(store.host_id(), runtime, 1))?;
    let mut large = SecurityEvent::heartbeat(store.host_id(), runtime, 2, 1, 1);
    large.logon_session = Some("x".repeat(256 * 1024));
    assert!(matches!(
        store.append_batch(&[large.clone()]),
        Err(StorageError::EventTooLarge)
    ));
    large.logon_session = Some("x".repeat(250 * 1024));
    let batch: Vec<_> = (2..12)
        .map(|sequence| {
            let mut event = large.clone();
            event.sequence = sequence;
            event.event_id = Uuid::new_v4();
            event
        })
        .collect();
    assert!(matches!(
        store.append_batch(&batch),
        Err(StorageError::DiskBudgetExceeded)
    ));
    assert_eq!(store.count()?, 1);
    assert_eq!(store.verify_integrity()?.verified_events, 1);
    Ok(())
}

#[test]
fn arbitrary_non_database_file_is_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    fs::write(directory.database(), b"not sqlite\0corrupt evidence")?;
    assert!(SqliteEventStore::open(directory.database(), StorageConfig::default()).is_err());
    Ok(())
}

#[test]
fn query_response_has_a_byte_budget_independent_of_row_limit() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let mut batch = events(store.host_id(), Uuid::new_v4(), 18);
    for event in &mut batch {
        event.logon_session = Some("x".repeat(240 * 1024));
    }
    for chunk in batch.chunks(9) {
        store.append_batch(chunk)?;
    }
    assert!(matches!(
        store.query(&EventQuery::default()),
        Err(StorageError::QueryResultTooLarge)
    ));
    assert_eq!(
        store
            .query(&EventQuery {
                limit: 10,
                ..EventQuery::default()
            })?
            .len(),
        10
    );
    Ok(())
}

#[test]
fn new_rule_backfill_is_idempotent_and_preserves_historical_events() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let mut batch = events(store.host_id(), Uuid::new_v4(), 8);
    for (event, id) in batch
        .iter_mut()
        .zip([4720, 4732, 4698, 4702, 5001, 5007, 1116, 1117])
    {
        let (channel, provider) = if id >= 5000 || id == 1116 || id == 1117 {
            (
                "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-Windows Defender",
            )
        } else {
            ("Security", "Microsoft-Windows-Security-Auditing")
        };
        event.sensor_id = format!("windows.event_log.{channel}");
        event.event_category = "windows_event_log".into();
        event.event_type = format!("windows.event_log.{id}");
        event.target = Some(piko_event_schema::EventTarget {
            kind: "windows_event_record".into(),
            identifier: format!("{channel}:{provider}:123"),
        });
    }
    store.append_batch(&batch)?;
    assert_eq!(store.alerts()?.len(), 8);
    let head = store.verify_integrity()?.head_hash;
    drop(store);
    let db = Connection::open(directory.database())?;
    db.execute("DELETE FROM detections", [])?;
    drop(db);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    assert_eq!(store.alerts()?.len(), 8);
    assert_eq!(store.verify_integrity()?.head_hash, head);
    drop(store);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    assert_eq!(store.alerts()?.len(), 8);
    assert_eq!(store.count()?, 8);
    Ok(())
}
#[test]
fn authentication_bursts_rebuild_after_restart_and_keep_review_identity(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    for sequence in 1..=6 {
        let mut event =
            SecurityEvent::heartbeat(store.host_id(), runtime, sequence, 1791885605000, sequence);
        event.sensor_id = "windows.event_log.Security".into();
        event.event_category = "windows_event_log".into();
        event.event_type = "windows.event_log.4625".into();
        event.target = Some(piko_event_schema::EventTarget {
            kind: "windows_event_record".into(),
            identifier: format!("Security:Microsoft-Windows-Security-Auditing:{sequence}"),
        });
        let raw=RawEvidence {evidence_id:Uuid::new_v4(),source:event.sensor_id.clone(),content_type:"application/xml; charset=utf-8".into(),observed_at_unix_ms:event.observation_time,bytes:format!(r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Version>0</Version><EventRecordID>{sequence}</EventRecordID><TimeCreated SystemTime="2026-10-13T10:00:05Z"/><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">PC</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="LogonType">3</Data><Data Name="Status">0xc000006d</Data><Data Name="SubStatus">0xc000006a</Data></EventData></Event>"#).into_bytes()};
        event.raw_evidence_reference = Some(raw.evidence_id);
        store.append_records(&[EventRecord {
            event,
            raw_evidence: Some(raw),
        }])?;
        if sequence == 4 {
            assert!(store.alerts()?.is_empty());
        }
    }
    let alerts = store.alerts()?;
    assert_eq!(alerts.len(), 1);
    let id = alerts[0].id.clone();
    assert_eq!(
        alerts[0]
            .assessment
            .as_ref()
            .ok_or("assessment")?
            .context
            .failed_logons
            .as_ref()
            .ok_or("summary")?
            .count,
        6
    );
    assert_eq!(store.verify_integrity()?.verified_events, 6);
    drop(store);
    let store = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    assert_eq!(store.alerts()?[0].id, id);
    let connection = Connection::open(directory.database())?;
    connection.execute("UPDATE raw_evidence SET digest=zeroblob(32)", [])?;
    assert!(matches!(store.alerts(), Err(StorageError::Corrupt(_))));
    Ok(())
}
#[test]
fn integrity_reader_never_creates_or_mutates_the_archive() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let missing = directory.0.join("missing.sqlite");
    assert!(SqliteEventStore::reader(&missing, StorageConfig::default()).is_err());
    assert!(!missing.exists());
    let mut writer = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    writer.append_batch(&events(writer.host_id(), runtime, 100))?;
    let mut reader = SqliteEventStore::reader(directory.database(), StorageConfig::default())?;
    assert_eq!(reader.verify_integrity()?.verified_events, 100);
    let e = SecurityEvent::heartbeat(writer.host_id(), Uuid::new_v4(), 1, 100, 1);
    assert!(reader.append_batch(std::slice::from_ref(&e)).is_err());
    assert_eq!(writer.count()?, 100);
    writer.append_batch(&[e])?;
    assert_eq!(reader.verify_integrity()?.verified_events, 101);
    assert_eq!(reader.verify_integrity()?, writer.verify_integrity()?);
    Ok(())
}
#[test]
fn readonly_verification_stays_coherent_during_concurrent_wal_appends() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new()?;
    let mut writer = SqliteEventStore::open(directory.database(), StorageConfig::default())?;
    for _ in 0..16 {
        writer.append_batch(&events(writer.host_id(), Uuid::new_v4(), 128))?;
    }
    let reader = SqliteEventStore::reader(directory.database(), StorageConfig::default())?;
    let host = writer.host_id();
    let background = std::thread::spawn(move || -> Result<u64, StorageError> {
        let runtime = Uuid::new_v4();
        for sequence in 1..=50 {
            writer.append_batch(&[SecurityEvent::heartbeat(
                host, runtime, sequence, 100, sequence,
            )])?;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        writer.count()
    });
    for _ in 0..5 {
        let report = reader.verify_integrity()?;
        assert!((2048..=2098).contains(&report.verified_events));
        assert!(report.head_hash.is_some());
        assert!(!report.externally_anchored);
    }
    assert_eq!(
        background.join().map_err(|_| "writer thread panicked")??,
        2098
    );
    assert_eq!(reader.verify_integrity()?.verified_events, 2098);
    Ok(())
}
#[test]
fn bundled_sqlite_includes_the_wal_reset_fix() {
    assert!(
        rusqlite::version_number() >= 3051003,
        "SQLite WAL reset fix required, got {}",
        rusqlite::version()
    );
}
