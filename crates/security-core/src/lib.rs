#![forbid(unsafe_code)]

use piko_event_schema::SecurityEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod assessment;
mod authentication;
mod identity_activity;
pub use authentication::{
    failed_logon_attempt, failed_logon_bursts, FailedLogonAttempt, FailedLogonSummary,
    LogonEvidence,
};
pub use identity_activity::{
    authentication_context, AuthenticationContext, AuthenticationIdentity, AuthenticationKind,
};
mod investigation;
pub use assessment::{assess, AlertAssessment, AlertContext, RiskFactor};
pub use investigation::{
    investigate, Investigation, InvestigationEdge, InvestigationNode, MAX_INVESTIGATION_EVENTS,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub event_id: Uuid,
    pub evidence_id: Option<Uuid>,
    pub observed_at: i64,
    /// Source event time, distinct from when piko collected an older record.
    #[serde(default)]
    pub event_time: Option<i64>,
    pub severity: String,
    pub title: String,
    pub explanation: String,
    /// A transparent triage heuristic, never a calibrated attack probability.
    #[serde(default)]
    pub assessment: Option<AlertAssessment>,
}

/// Rules use normalized source identity, never the severity of an arbitrary
/// provider, and never infer an attacker from the Event Log emitter's PID.
pub fn detect(event: &SecurityEvent) -> Option<Alert> {
    let target = event.target.as_ref()?;
    if event.event_category != "windows_event_log" || target.kind != "windows_event_record" {
        return None;
    }
    let mut parts = target.identifier.split(':');
    let (channel, provider, record) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || record.parse::<u64>().is_err()
        || event.sensor_id != format!("windows.event_log.{channel}")
    {
        return None;
    }
    let (rule, severity, title, explanation) = match (channel, provider, event.event_type.as_str()) {
        ("Security", "Microsoft-Windows-Eventlog", "windows.event_log.1102") => (
            "audit-log-cleared", "high", "Registro Security cancellato",
            "Windows registra la cancellazione del log di sicurezza. Può essere manutenzione autorizzata o rimozione di tracce: verificare l'identità nel documento XML. Non prova da sola un attacco."),
        ("System", "Microsoft-Windows-Eventlog", "windows.event_log.104") => (
            "event-log-cleared", "medium", "Registro eventi cancellato",
            "Il provider Eventlog segnala la cancellazione di un registro. Verificare canale e autore nell'evidenza; nessuna azione automatica è autorizzata."),
        ("Security", "Microsoft-Windows-Security-Auditing", "windows.event_log.4719") => (
            "audit-policy-changed", "medium", "Policy di audit modificata",
            "Windows registra una modifica alla policy di audit. Confrontare le categorie modificate con la configurazione prevista; può essere un intervento amministrativo legittimo."),
        ("System", "Service Control Manager", "windows.event_log.7045") => (
            "service-installed", "low", "Nuovo servizio installato",
            "Windows registra l'installazione di un servizio. Esaminare percorso, account e modalità di avvio nell'XML. L'installazione non equivale a malware."),
        ("Security", "Microsoft-Windows-Security-Auditing", "windows.event_log.4720") => ("account-created", "medium", "Account creato", "Windows registra la creazione di un account. Verificare nome e autore nell’evidenza; la creazione può essere autorizzata."),
        ("Security", "Microsoft-Windows-Security-Auditing", "windows.event_log.4732") => ("group-member-added", "medium", "Membro aggiunto a un gruppo locale", "Windows registra una nuova appartenenza a un gruppo. Verificare gruppo e membro; non ogni gruppo concede privilegi amministrativi."),
        ("Security", "Microsoft-Windows-Security-Auditing", "windows.event_log.4698") => ("scheduled-task-created", "medium", "Attività pianificata creata", "Windows registra una nuova attività pianificata. Verificare nome, comando e autorizzazione: non dimostra esecuzione né persistenza ostile."),
        ("Security", "Microsoft-Windows-Security-Auditing", "windows.event_log.4702") => ("scheduled-task-updated", "medium", "Attività pianificata modificata", "Windows registra una modifica a un’attività pianificata. Confrontare l’evidenza con le modifiche autorizzate."),
        ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "windows.event_log.5001") => ("defender-realtime-disabled", "high", "Defender: protezione in tempo reale disattivata", "Defender segnala la disattivazione della protezione in tempo reale all’ora dell’evento. Lo stato attuale deve essere verificato in Sicurezza di Windows."),
        ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "windows.event_log.5007") => ("defender-config-changed", "low", "Defender: configurazione modificata", "Defender registra una modifica alla configurazione. Non dimostra che la protezione sia stata disattivata; aggiornamenti e amministratori possono modificarla."),
        ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "windows.event_log.1116") => ("defender-threat-reported", "high", "Defender ha segnalato una minaccia", "Il motore Microsoft Defender ha registrato una rilevazione. Controllare nome, risorsa e stato in Cronologia protezione; piko non ha effettuato una scansione propria."),
        ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "windows.event_log.1117") => ("defender-action-reported", "medium", "Defender ha registrato un’azione", "Defender registra un’azione relativa a una rilevazione. L’azione può anche consentire il file: questo evento da solo non conferma che la minaccia sia stata eliminata."),
        _ => return None,
    };
    Some(Alert {
        id: format!("{rule}:{}", event.event_id),
        rule_id: rule.into(),
        rule_version: 1,
        event_id: event.event_id,
        evidence_id: event.raw_evidence_reference,
        observed_at: event.observation_time,
        event_time: Some(event.wall_clock_time),
        severity: severity.into(),
        title: title.into(),
        explanation: explanation.into(),
        assessment: None,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Quarantine,
    Restore,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    pub requested_by: String,
    pub confirmed_by: Option<String>,
    pub id: Uuid,
    pub kind: ActionKind,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub file_identity: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub detail: String,
    pub backup_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseStatus {
    pub roots: Vec<String>,
    pub max_file_bytes: u64,
    pub vault_budget_bytes: u64,
    pub actions: Vec<Action>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use piko_event_schema::EventTarget;
    #[test]
    fn all_rules_preserve_evidence_without_promoting_unknown_events() {
        for (channel, provider, id, expected) in [
            (
                "Security",
                "Microsoft-Windows-Eventlog",
                1102,
                "audit-log-cleared",
            ),
            (
                "Security",
                "Microsoft-Windows-Security-Auditing",
                4719,
                "audit-policy-changed",
            ),
            (
                "System",
                "Microsoft-Windows-Eventlog",
                104,
                "event-log-cleared",
            ),
            (
                "System",
                "Service Control Manager",
                7045,
                "service-installed",
            ),
        ] {
            let mut e = SecurityEvent::heartbeat(Uuid::nil(), Uuid::nil(), 1, 1, 1);
            e.sensor_id = format!("windows.event_log.{channel}");
            e.event_category = "windows_event_log".into();
            e.event_type = format!("windows.event_log.{id}");
            e.raw_evidence_reference = Some(Uuid::from_u128(123));
            e.wall_clock_time = 100;
            e.observation_time = 500;
            e.target = Some(EventTarget {
                kind: "windows_event_record".into(),
                identifier: format!("{channel}:{provider}:42"),
            });
            let alert = detect(&e).expect("matching rule");
            assert_eq!(alert.rule_id, expected);
            assert_eq!(alert.evidence_id, e.raw_evidence_reference);
            assert_eq!(alert.event_time, Some(100));
            assert_eq!(alert.observed_at, 500);
            e.event_type = "windows.event_log.9999".into();
            e.severity = piko_event_schema::Severity::Critical;
            assert!(detect(&e).is_none());
        }
    }
    #[test]
    fn exact_source_and_rule_are_required() {
        let mut e = SecurityEvent::heartbeat(Uuid::nil(), Uuid::nil(), 1, 1, 1);
        e.event_category = "windows_event_log".into();
        e.sensor_id = "windows.event_log.System".into();
        e.event_type = "windows.event_log.7045".into();
        e.target = Some(EventTarget {
            kind: "windows_event_record".into(),
            identifier: "System:Service Control Manager:42".into(),
        });
        let a = detect(&e).expect("matched rule");
        assert_eq!(a.severity, "low");
        assert_eq!(a.event_id, e.event_id);
        assert_eq!(detect(&e).expect("stable").id, a.id);
        e.sensor_id = "windows.event_log.Application".into();
        assert!(detect(&e).is_none());
        e.sensor_id = "windows.event_log.System".into();
        e.target.as_mut().expect("target").identifier = "System:Untrusted:42".into();
        assert!(detect(&e).is_none());
    }
}
