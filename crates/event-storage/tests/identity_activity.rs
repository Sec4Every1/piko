use piko_event_schema::{EventRecord, EventTarget, RawEvidence, SecurityEvent};
use piko_event_storage::{AuthenticationQuery, SqliteEventStore, StorageConfig};
use piko_security_core::AuthenticationKind;
use uuid::Uuid;
#[test]
fn identity_filter_and_cursor_precede_limit_and_preserve_original_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("piko-identity-{}.db", Uuid::new_v4()));
    let mut store = SqliteEventStore::open(path, StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    for sequence in 1..=30 {
        let id = if sequence % 3 == 0 {
            4624
        } else if sequence % 3 == 1 {
            4648
        } else {
            5156
        };
        let mut e = SecurityEvent::heartbeat(store.host_id(), runtime, sequence, 1000, 1);
        e.sensor_id = "windows.event_log.Security".into();
        e.event_category = "windows_event_log".into();
        e.event_type = format!("windows.event_log.{id}");
        e.target = Some(EventTarget {
            kind: "windows_event_record".into(),
            identifier: format!("Security:Microsoft-Windows-Security-Auditing:{sequence}"),
        });
        let raw=RawEvidence{evidence_id:Uuid::new_v4(),source:e.sensor_id.clone(),content_type:"application/xml; charset=utf-8".into(),observed_at_unix_ms:1000,bytes:format!(r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{id}</EventID><Version>0</Version><EventRecordID>{sequence}</EventRecordID><TimeCreated SystemTime="1970-01-01T00:00:01Z"/><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data></EventData></Event>"#).into_bytes()};
        e.raw_evidence_reference = Some(raw.evidence_id);
        store.append_records(&[EventRecord {
            event: e,
            raw_evidence: Some(raw),
        }])?;
    }
    let before = store.verify_integrity()?;
    let mut cursor = None;
    let mut seen = Vec::new();
    loop {
        let page = store.authentication_activity(&AuthenticationQuery {
            before_position: cursor,
            ..Default::default()
        })?;
        for row in &page.records {
            assert_eq!(row.context.evidence_status, "verified");
            assert_eq!(row.context.account.name.as_deref(), Some("alice"));
            assert!(row.event.event_type != "windows.event_log.5156");
            assert!(!seen.contains(&row.position));
            seen.push(row.position);
        }
        cursor = page.next_before;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 20);
    assert!(seen.windows(2).all(|p| p[0] > p[1]));
    let page = store.authentication_activity(&AuthenticationQuery {
        kind: Some(AuthenticationKind::SuccessfulLogon),
        ..Default::default()
    })?;
    assert_eq!(page.records.len(), 5);
    assert!(page
        .records
        .iter()
        .all(|r| r.kind == AuthenticationKind::SuccessfulLogon));
    assert!(store
        .authentication_activity(&AuthenticationQuery {
            limit: 21,
            ..Default::default()
        })
        .is_err());
    assert!(store
        .authentication_activity(&AuthenticationQuery {
            before_position: Some(0),
            ..Default::default()
        })
        .is_err());
    assert_eq!(store.verify_integrity()?, before);
    Ok(())
}
