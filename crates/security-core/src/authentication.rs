//! Repeated bad-credential observations in fixed UTC minute buckets, not an attack verdict.
use crate::{assessment::extract_context, Alert, AlertAssessment, AlertContext, RiskFactor};
use piko_event_schema::{RawEvidence, SecurityEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogonEvidence {
    pub event_id: Uuid,
    pub evidence_id: Uuid,
    pub event_time: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedLogonSummary {
    pub bucket_start: i64,
    pub bucket_end: i64,
    pub count: u32,
    pub records: Vec<LogonEvidence>,
}
pub struct FailedLogonAttempt {
    event: SecurityEvent,
    context: AlertContext,
    source_record: String,
    key: (Uuid, i64, String, String, String, String),
}
pub fn failed_logon_attempt(
    event: &SecurityEvent,
    raw: &RawEvidence,
) -> Option<FailedLogonAttempt> {
    let target = event.target.as_ref()?;
    if event.event_category != "windows_event_log"
        || event.sensor_id != "windows.event_log.Security"
        || event.event_type != "windows.event_log.4625"
        || target.kind != "windows_event_record"
        || !target
            .identifier
            .starts_with("Security:Microsoft-Windows-Security-Auditing:")
        || event.wall_clock_time <= 0
        || event.wall_clock_time > 8640000000000
    {
        return None;
    }
    let record = target
        .identifier
        .strip_prefix("Security:Microsoft-Windows-Security-Auditing:")?;
    if record.parse::<u64>().ok()? == 0 {
        return None;
    }
    let context = extract_context(event, raw).ok()?;
    let user = context.target_user.as_deref()?.trim();
    let domain = context.target_domain.as_deref()?.trim();
    if user.is_empty() || user == "-" || domain.is_empty() || domain == "-" {
        return None;
    }
    let ip: std::net::IpAddr = context.source_ip.as_deref()?.parse().ok()?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return None;
    }
    let ip = match ip {
        std::net::IpAddr::V6(v) if v.to_ipv4_mapped().is_some() => {
            std::net::IpAddr::V4(v.to_ipv4_mapped()?)
        }
        v => v,
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    let logon = context.logon_type.as_deref()?;
    if !["3", "10"].contains(&logon) {
        return None;
    }
    let status = context.failure_status.as_deref()?.to_ascii_lowercase();
    let sub = context
        .failure_sub_status
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !(["0xc0000064", "0xc000006a"].contains(&status.as_str())
        || status == "0xc000006d" && ["0xc0000064", "0xc000006a"].contains(&sub.as_str()))
    {
        return None;
    }
    let key = (
        event.host_id,
        event.wall_clock_time / 60000 * 60000,
        domain.to_owned(),
        user.to_owned(),
        ip.to_string(),
        logon.to_owned(),
    );
    Some(FailedLogonAttempt {
        event: event.clone(),
        context,
        source_record: target.identifier.clone(),
        key,
    })
}
pub fn failed_logon_bursts(attempts: Vec<FailedLogonAttempt>) -> Vec<Alert> {
    if attempts.len() > 256 {
        return Vec::new();
    }
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for attempt in attempts {
        // Event Log bookmarks can replay a record under a new runtime UUID.
        if seen.insert((
            attempt.event.host_id,
            attempt.source_record.clone(),
            attempt.event.wall_clock_time,
        )) {
            groups.entry(attempt.key.clone()).or_default().push(attempt);
        }
    }
    let mut alerts = Vec::new();
    for (key, mut group) in groups {
        if group.len() < 5 {
            continue;
        }
        group.sort_by_key(|a| (a.event.wall_clock_time, a.event.event_id));
        let records = group
            .iter()
            .filter_map(|a| {
                a.event
                    .raw_evidence_reference
                    .map(|evidence_id| LogonEvidence {
                        event_id: a.event.event_id,
                        evidence_id,
                        event_time: a.event.wall_clock_time,
                    })
            })
            .collect::<Vec<_>>();
        let last = group.pop().expect("non-empty qualifying group");
        let mut context = last.context;
        context.failed_logons = Some(FailedLogonSummary {
            bucket_start: key.1,
            bucket_end: key.1 + 60000,
            count: records.len() as u32,
            records,
        });
        // Length-prefix every key component; names/addresses cannot create collisions by separators.
        let mut hash = Sha256::new();
        for part in [
            key.0.to_string(),
            key.1.to_string(),
            key.2,
            key.3,
            key.4,
            key.5,
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part.as_bytes());
        }
        let id = format!("failed-logon-burst:{:x}", hash.finalize());
        alerts.push(Alert {id,rule_id:"failed-logon-burst".into(),rule_version:1,event_id:last.event.event_id,evidence_id:last.event.raw_evidence_reference,observed_at:last.event.observation_time,event_time:Some(last.event.wall_clock_time),severity:"medium".into(),title:"Tentativi di accesso ripetuti".into(),explanation:"Almeno cinque errori di credenziali per lo stesso account, indirizzo e tipo di accesso nella stessa finestra UTC di un minuto. Può dipendere anche da credenziali salvate non aggiornate; nessun blocco automatico.".into(),assessment:Some(AlertAssessment {model_version:"piko-risk-v1".into(),risk_score:50,false_positive_probability:None,factors:vec![RiskFactor {code:"repeated_bad_credentials".into(),points:50}],context})});
    }
    alerts
}
#[cfg(test)]
mod tests {
    use super::*;
    use piko_event_schema::EventTarget;
    fn fixture(sequence: u64, extra: &str) -> (SecurityEvent, RawEvidence) {
        let mut e = SecurityEvent::heartbeat(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            sequence,
            1791885605000,
            1,
        );
        e.sensor_id = "windows.event_log.Security".into();
        e.event_category = "windows_event_log".into();
        e.event_type = "windows.event_log.4625".into();
        e.target = Some(EventTarget {
            kind: "windows_event_record".into(),
            identifier: format!("Security:Microsoft-Windows-Security-Auditing:{sequence}"),
        });
        let r=RawEvidence{evidence_id:Uuid::new_v4(),source:e.sensor_id.clone(),content_type:"application/xml; charset=utf-8".into(),observed_at_unix_ms:e.observation_time,bytes:format!(r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Version>0</Version><EventRecordID>{sequence}</EventRecordID><TimeCreated SystemTime="2026-10-13T10:00:05Z"/><Execution ProcessID="888"/><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">PC</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="LogonType">10</Data><Data Name="Status">0xc000006d</Data><Data Name="SubStatus">0xc000006a</Data><Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>{extra}</EventData></Event>"#).into_bytes()};
        e.raw_evidence_reference = Some(r.evidence_id);
        (e, r)
    }
    #[test]
    fn threshold_keeps_references_names_and_stable_bucket_identity() {
        let pairs = (1..=5).map(|i| fixture(i, "")).collect::<Vec<_>>();
        let attempt = |i: usize| failed_logon_attempt(&pairs[i].0, &pairs[i].1).expect("valid XML");
        assert!(failed_logon_bursts((0..4).map(attempt).collect()).is_empty());
        let first = failed_logon_bursts((0..5).map(attempt).collect());
        assert_eq!(first.len(), 1);
        let ctx = &first[0].assessment.as_ref().expect("assessment").context;
        assert_eq!(ctx.target_user.as_deref(), Some("alice"));
        assert_eq!(ctx.installer_process, None);
        assert_eq!(
            ctx.failed_logons.as_ref().expect("summary").records.len(),
            5
        );
        let (e, r) = fixture(6, "");
        let mut six = (0..5).map(attempt).collect::<Vec<_>>();
        six.push(failed_logon_attempt(&e, &r).expect("sixth"));
        assert_eq!(failed_logon_bursts(six)[0].id, first[0].id);
    }
    #[test]
    fn replay_does_not_count_twice_and_exact_fields_are_required() {
        let (mut e, r) = fixture(1, "");
        let mut attempts = Vec::new();
        for _ in 0..5 {
            e.event_id = Uuid::new_v4();
            attempts.push(failed_logon_attempt(&e, &r).expect("attempt"));
        }
        assert!(failed_logon_bursts(attempts).is_empty());
        for (from, to) in [
            ("192.0.2.10", "::ffff:127.0.0.1"),
            ("<Version>0", "<Version>1"),
            ("0xc000006a", "0xc0000234"),
            ("<Data Name=\"LogonType\">10", "<Data Name=\"LogonType\">2"),
            ("10:00:05Z", "10:00:06Z"),
        ] {
            let mut bad = r.clone();
            bad.bytes = String::from_utf8(r.bytes.clone())
                .expect("XML")
                .replace(from, to)
                .into_bytes();
            assert!(failed_logon_attempt(&e, &bad).is_none(), "{to}");
        }
        let (e, r) = fixture(1, "<Data Name=\"IpAddress\">192.0.2.10</Data>");
        assert!(failed_logon_attempt(&e, &r).is_none());
    }
    #[test]
    fn different_accounts_sources_types_and_minutes_never_mix() {
        let pairs = (1..=5).map(|i| fixture(i, "")).collect::<Vec<_>>();
        for (from, to) in [
            ("alice", "bob"),
            ("192.0.2.10", "192.0.2.11"),
            ("<Data Name=\"LogonType\">10", "<Data Name=\"LogonType\">3"),
            ("PC</Data>", "OTHER</Data>"),
        ] {
            let mut attempts = Vec::new();
            for (i, (e, r)) in pairs.iter().enumerate() {
                let mut raw = r.clone();
                if i == 4 {
                    raw.bytes = String::from_utf8(raw.bytes)
                        .expect("XML")
                        .replace(from, to)
                        .into_bytes();
                }
                attempts.push(failed_logon_attempt(e, &raw).expect("valid separate group"));
            }
            assert!(failed_logon_bursts(attempts).is_empty());
        }
        let mut attempts = (0..4)
            .map(|i| failed_logon_attempt(&pairs[i].0, &pairs[i].1).expect("valid"))
            .collect::<Vec<_>>();
        let (mut e, mut r) = fixture(5, "");
        e.wall_clock_time += 60000;
        r.bytes = String::from_utf8(r.bytes)
            .expect("XML")
            .replace("10:00:05Z", "10:01:05Z")
            .into_bytes();
        attempts.push(failed_logon_attempt(&e, &r).expect("next minute"));
        assert!(failed_logon_bursts(attempts).is_empty());
    }
}
