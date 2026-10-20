use piko_event_schema::{EventTarget, RawEvidence, SecurityEvent};
use piko_security_core::{authentication_context, AuthenticationKind};
use uuid::Uuid;
fn fixture(id: u32, version: u32, data: &str) -> (SecurityEvent, RawEvidence) {
    let mut event = SecurityEvent::heartbeat(Uuid::from_u128(1), Uuid::from_u128(2), 1, 1000, 1);
    event.sensor_id = "windows.event_log.Security".into();
    event.event_category = "windows_event_log".into();
    event.event_type = format!("windows.event_log.{id}");
    event.target = Some(EventTarget {
        kind: "windows_event_record".into(),
        identifier: "Security:Microsoft-Windows-Security-Auditing:42".into(),
    });
    let raw=RawEvidence{evidence_id:Uuid::new_v4(),source:event.sensor_id.clone(),content_type:"application/xml; charset=utf-8".into(),observed_at_unix_ms:1000,bytes:format!(r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{id}</EventID><Version>{version}</Version><EventRecordID>42</EventRecordID><TimeCreated SystemTime="1970-01-01T00:00:01Z"/><Execution ProcessID="888"/><Channel>Security</Channel></System><EventData>{data}</EventData></Event>"#).into_bytes()};
    event.raw_evidence_reference = Some(raw.evidence_id);
    (event, raw)
}
const FIELDS: &str = r#"<Data Name="SubjectUserName">requester</Data><Data Name="SubjectDomainName">PC</Data><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="SubjectLogonId">0x3e7</Data><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">DOMAIN</Data><Data Name="TargetUserSid">S-1-5-21-1</Data><Data Name="TargetLogonId">0xABCD</Data><Data Name="LogonType">10</Data><Data Name="ProcessId">0xaa4</Data><Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data><Data Name="IpAddress">192.0.2.10</Data>"#;
#[test]
fn account_management_uses_target_sid_and_never_invents_caller_or_logon() {
    for (id, kind) in [
        (4720, AuthenticationKind::AccountCreated),
        (4722, AuthenticationKind::AccountEnabled),
        (4725, AuthenticationKind::AccountDisabled),
        (4726, AuthenticationKind::AccountDeleted),
    ] {
        let fields = format!("{FIELDS}<Data Name=\"TargetSid\">S-1-5-21-42</Data>");
        let (event, raw) = fixture(id, 0, &fields);
        let context = authentication_context(&event, Some(&raw));
        assert_eq!(
            AuthenticationKind::from_event_type(&event.event_type),
            Some(kind)
        );
        assert_eq!(context.evidence_status, "verified");
        assert_eq!(context.account.sid.as_deref(), Some("S-1-5-21-42"));
        assert_eq!(context.account.name.as_deref(), Some("alice"));
        assert_eq!(context.subject.name.as_deref(), Some("requester"));
        assert_eq!(context.logon_id.as_deref(), Some("0x3e7"));
        assert!(context.caller_pid.is_none());
        assert!(context.caller_path.is_none());
        assert!(context.address.is_none());
        assert!(context.logon_type.is_none());
        let (event, raw) = fixture(id, 0, FIELDS);
        assert!(authentication_context(&event, Some(&raw))
            .account
            .sid
            .is_none());
        let (event, raw) = fixture(id, 1, &fields);
        let unsupported = authentication_context(&event, Some(&raw));
        assert_eq!(unsupported.evidence_status, "unsupported_version");
        assert!(unsupported.account.name.is_none());
    }
}
#[test]
fn reviewed_versions_keep_account_subject_and_payload_pid_separate() {
    for version in 0..=3 {
        let (e, r) = fixture(4624, version, FIELDS);
        let c = authentication_context(&e, Some(&r));
        assert_eq!(c.evidence_status, "verified");
        assert_eq!(c.account.name.as_deref(), Some("alice"));
        assert_eq!(c.subject.name.as_deref(), Some("requester"));
        assert_eq!(c.caller_pid, Some(2724));
        assert_eq!(c.logon_type, Some(10));
        assert_eq!(c.logon_id.as_deref(), Some("0xabcd"));
        assert_eq!(c.address.as_deref(), Some("192.0.2.10"));
    }
    let (e, r) = fixture(4648, 0, FIELDS);
    let c = authentication_context(&e, Some(&r));
    assert_eq!(c.logon_id.as_deref(), Some("0x3e7"));
    assert_eq!(
        AuthenticationKind::from_event_type(&e.event_type),
        Some(AuthenticationKind::ExplicitCredentials)
    );
    let (e, r) = fixture(
        4672,
        0,
        &format!("{FIELDS}<Data Name=\"PrivilegeList\">SeDebugPrivilege\nSeBackupPrivilege</Data>"),
    );
    let c = authentication_context(&e, Some(&r));
    assert_eq!(c.account.name.as_deref(), Some("requester"));
    assert_eq!(c.privileges, vec!["SeDebugPrivilege", "SeBackupPrivilege"]);
}
#[test]
fn mismatched_unknown_and_ambiguous_evidence_never_becomes_identity() {
    let (e, r) = fixture(4624, 2, FIELDS);
    for (from, to) in [
        ("<Version>2", "<Version>9"),
        ("<EventRecordID>42", "<EventRecordID>43"),
        ("00:00:01Z", "00:00:02Z"),
        ("Microsoft-Windows-Security-Auditing", "OtherProvider"),
        ("<Channel>Security", "<Channel>System"),
        (
            "</EventData>",
            "<Data Name=\"TargetUserName\">mallory</Data></EventData>",
        ),
        (
            "<EventData>",
            "<EventData xmlns=\"https://invalid.example\">",
        ),
        ("<Event ", "<!DOCTYPE Event [<!ENTITY x \"alice\">]><Event "),
    ] {
        let mut bad = r.clone();
        bad.bytes = String::from_utf8(r.bytes.clone())
            .unwrap()
            .replace(from, to)
            .into_bytes();
        let c = authentication_context(&e, Some(&bad));
        assert_ne!(c.evidence_status, "verified");
        assert!(c.account.name.is_none());
        assert!(c.caller_pid.is_none());
    }
    let mut bad = r.clone();
    bad.evidence_id = Uuid::new_v4();
    assert_eq!(
        authentication_context(&e, Some(&bad)).evidence_status,
        "invalid"
    );
    assert_eq!(authentication_context(&e, None).evidence_status, "missing");
    let(e,r)=fixture(4625,0,"<Data Name=\"ProcessId\">0x100000000</Data><Data Name=\"TargetUserName\">-</Data><Data Name=\"IpAddress\">not-an-ip</Data><Data Name=\"TargetLogonId\">0x0</Data>");
    let c = authentication_context(&e, Some(&r));
    assert_eq!(c.evidence_status, "verified");
    assert!(c.caller_pid.is_none());
    assert!(c.account.name.is_none());
    assert!(c.address.is_none());
    assert!(c.logon_id.is_none());
}
