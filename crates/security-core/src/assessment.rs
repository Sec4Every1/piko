use crate::{detect, Alert};
use piko_event_schema::{RawEvidence, SecurityEvent};
use quick_xml::{events::Event, Reader, XmlVersion};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const EVENT_NS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";
const LOG_NS: &str = "http://manifests.microsoft.com/win/2004/08/windows/eventlog";
const MAX_FIELD: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskFactor {
    pub code: String,
    pub points: i16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertAssessment {
    pub model_version: String,
    /// Sum of documented triage weights, clamped to 0..100. Not a percentage.
    pub risk_score: u8,
    /// No labelled calibration dataset exists; this is always None in v1.
    pub false_positive_probability: Option<f64>,
    pub factors: Vec<RiskFactor>,
    pub context: AlertContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertContext {
    /// verified means matching evidence identity/source/schema, not trusted code.
    pub evidence_status: String,
    pub service_name: Option<String>,
    /// Observed service command line, not proof that the executable ran.
    pub image_path: Option<String>,
    pub subject_user: Option<String>,
    pub subject_domain: Option<String>,
    pub service_account: Option<String>,
    pub log_channel: Option<String>,
    pub audit_changes: Option<String>,
    #[serde(default)]
    pub target_user: Option<String>,
    #[serde(default)]
    pub target_domain: Option<String>,
    #[serde(default)]
    pub group_name: Option<String>,
    #[serde(default)]
    pub group_sid: Option<String>,
    #[serde(default)]
    pub member_sid: Option<String>,
    #[serde(default)]
    pub task_name: Option<String>,
    #[serde(default)]
    pub threat_name: Option<String>,
    #[serde(default)]
    pub resource_path: Option<String>,
    #[serde(default)]
    pub defender_action: Option<String>,
    #[serde(default)]
    pub old_value: Option<String>,
    #[serde(default)]
    pub new_value: Option<String>,
    /// These events do not identify the installing/acting process.
    pub installer_process: Option<String>,
    #[serde(default)]
    pub failed_logons: Option<crate::FailedLogonSummary>,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub logon_type: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub failure_status: Option<String>,
    #[serde(default)]
    pub failure_sub_status: Option<String>,
}

impl AlertContext {
    fn empty(status: &str) -> Self {
        Self {
            evidence_status: status.into(),
            service_name: None,
            image_path: None,
            subject_user: None,
            subject_domain: None,
            service_account: None,
            log_channel: None,
            audit_changes: None,
            target_user: None,
            target_domain: None,
            group_name: None,
            group_sid: None,
            member_sid: None,
            task_name: None,
            threat_name: None,
            resource_path: None,
            defender_action: None,
            old_value: None,
            new_value: None,
            installer_process: None,
            failed_logons: None,
            source_ip: None,
            logon_type: None,
            caller_path: None,
            failure_status: None,
            failure_sub_status: None,
        }
    }
}

/// Rebuild from the normalized event and its original evidence. Never trust a
/// previously serialized assessment or infer actor identity from Execution PID.
pub fn assess(alert: &mut Alert, event: &SecurityEvent, raw: Option<&RawEvidence>) {
    alert.assessment = None;
    let Some(expected) = detect(event) else {
        return;
    };
    if alert.rule_version != 1
        || alert.id != expected.id
        || alert.rule_id != expected.rule_id
        || alert.event_id != event.event_id
        || alert.evidence_id != event.raw_evidence_reference
    {
        return;
    }
    let (code, points) = match alert.rule_id.as_str() {
        "audit-log-cleared" => ("audit_log_cleared", 70),
        "event-log-cleared" => ("event_log_cleared", 50),
        "audit-policy-changed" => ("audit_policy_changed", 40),
        "service-installed" => ("service_installed", 25),
        "account-created" => ("account_created", 40),
        "group-member-added" => ("group_member_added", 45),
        "scheduled-task-created" => ("scheduled_task_created", 35),
        "scheduled-task-updated" => ("scheduled_task_updated", 40),
        "defender-realtime-disabled" => ("defender_realtime_disabled", 75),
        "defender-config-changed" => ("defender_config_changed", 25),
        "defender-threat-reported" => ("defender_threat_reported", 80),
        "defender-action-reported" => ("defender_action_reported", 45),
        _ => return,
    };
    let mut factors = vec![RiskFactor {
        code: code.into(),
        points,
    }];
    let context = match raw {
        None => AlertContext::empty("missing"),
        Some(raw) => match extract_context(event, raw) {
            Ok(context) => context,
            Err(status) => AlertContext::empty(status),
        },
    };
    match context.evidence_status.as_str() {
        "missing" => factor(&mut factors, "evidence_missing", 0),
        "invalid" => factor(&mut factors, "evidence_invalid", 0),
        "unsupported_version" => factor(&mut factors, "evidence_version_unsupported", 0),
        _ => {}
    }
    if alert.rule_id == "service-installed" && context.evidence_status == "verified" {
        if context
            .image_path
            .as_deref()
            .is_some_and(untrusted_location)
        {
            factor(&mut factors, "service_untrusted_location", 20);
        }
        if context.service_name.is_none() || context.image_path.is_none() {
            factor(&mut factors, "service_details_missing", 0);
        }
    }
    if alert.rule_id == "audit-policy-changed" && context.evidence_status == "verified" {
        match context.audit_changes.as_deref().and_then(audit_change) {
            Some(true) => factor(&mut factors, "audit_logging_removed", 25),
            Some(false) => factor(&mut factors, "audit_logging_added_only", -15),
            None => factor(&mut factors, "audit_change_unknown", 0),
        }
    }
    let risk_score = factors
        .iter()
        .map(|factor| factor.points)
        .sum::<i16>()
        .clamp(0, 100) as u8;
    alert.assessment = Some(AlertAssessment {
        model_version: "piko-risk-v1".into(),
        risk_score,
        false_positive_probability: None,
        factors,
        context,
    });
}

fn factor(factors: &mut Vec<RiskFactor>, code: &str, points: i16) {
    factors.push(RiskFactor {
        code: code.into(),
        points,
    });
}

/// Lexical indicator only: no file existence, signature, or ACL assertion. The
/// check concerns the executable portion, never a directory in an argument.
fn untrusted_location(command: &str) -> bool {
    let command = command.trim();
    let binary = if let Some(quoted) = command.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            return false;
        };
        &quoted[..end]
    } else {
        command.split_whitespace().next().unwrap_or("")
    };
    let path = binary.replace('/', "\\").to_ascii_lowercase();
    path.starts_with("%temp%\\")
        || path.starts_with("%tmp%\\")
        || path.starts_with("%userprofile%\\")
        || (path.as_bytes().get(1) == Some(&b':')
            && path.get(2..).is_some_and(|tail| {
                tail.starts_with("\\users\\")
                    || tail.starts_with("\\windows\\temp\\")
                    || tail.starts_with("\\temp\\")
            }))
}

/// Canonical Windows message tokens. Unknown/localized text is left unknown;
/// an addition is not treated as disabled logging (Microsoft event 4719).
fn audit_change(value: &str) -> Option<bool> {
    let tokens: Vec<_> = value.split(',').map(str::trim).collect();
    if tokens.is_empty()
        || tokens.len() > 4
        || tokens
            .iter()
            .any(|token| !["%%8448", "%%8449", "%%8450", "%%8451"].contains(token))
    {
        return None;
    }
    Some(
        tokens
            .iter()
            .any(|token| ["%%8448", "%%8450"].contains(token)),
    )
}

pub(crate) fn extract_context(
    event: &SecurityEvent,
    raw: &RawEvidence,
) -> Result<AlertContext, &'static str> {
    if event.raw_evidence_reference != Some(raw.evidence_id)
        || raw.source != event.sensor_id
        || raw.content_type != "application/xml; charset=utf-8"
        || raw.bytes.len() > 192 * 1024
    {
        return Err("invalid");
    }
    let xml = std::str::from_utf8(&raw.bytes).map_err(|_| "invalid")?;
    let tree = parse_xml(xml).map_err(|_| "invalid")?;
    if tree.name != "Event" || tree.namespace != EVENT_NS {
        return Err("invalid");
    }
    let system = tree.one("System")?.ok_or("invalid")?;
    let target = event.target.as_ref().ok_or("invalid")?;
    let expected: Vec<_> = target.identifier.split(':').collect();
    if expected.len() != 3 {
        return Err("invalid");
    }
    let provider = system.one("Provider")?.ok_or("invalid")?;
    let event_type = format!(
        "windows.event_log.{}",
        system.text_of("EventID")?.ok_or("invalid")?
    );
    if provider.attrs.get("Name").map(String::as_str) != Some(expected[1])
        || system.text_of("Channel")?.as_deref() != Some(expected[0])
        || system.text_of("EventRecordID")?.as_deref() != Some(expected[2])
        || event_type != event.event_type
    {
        return Err("invalid");
    }
    let version = system.text_of("Version")?;
    let supported = version.as_deref() == Some("0")
        || (version.as_deref() == Some("1")
            && ["windows.event_log.4698", "windows.event_log.4702"]
                .contains(&event.event_type.as_str()));
    if !supported {
        return Err("unsupported_version");
    }
    let mut context = AlertContext::empty("verified");
    match event.event_type.as_str() {
        "windows.event_log.4625"
        | "windows.event_log.7045"
        | "windows.event_log.4719"
        | "windows.event_log.4720"
        | "windows.event_log.4732"
        | "windows.event_log.4698"
        | "windows.event_log.4702"
        | "windows.event_log.5001"
        | "windows.event_log.5007"
        | "windows.event_log.1116"
        | "windows.event_log.1117" => {
            if tree.one("UserData")?.is_some() {
                return Err("invalid");
            }
            let data = tree.one("EventData")?.ok_or("invalid")?;
            let mut fields = BTreeMap::new();
            for field in &data.children {
                if field.name != "Data" || field.namespace != EVENT_NS || !field.children.is_empty()
                {
                    return Err("invalid");
                }
                let name = field.attrs.get("Name").ok_or("invalid")?;
                if fields.insert(name.as_str(), field.text.trim()).is_some() {
                    return Err("invalid");
                }
            }
            let get = |name| {
                fields
                    .get(name)
                    .filter(|text| !text.is_empty())
                    .map(|text| (*text).to_owned())
            };
            if event.event_type == "windows.event_log.7045" {
                context.service_name = get("ServiceName");
                context.image_path = get("ImagePath");
                context.service_account = get("AccountName");
            } else {
                context.subject_user = get("SubjectUserName");
                context.subject_domain = get("SubjectDomainName");
                context.audit_changes = get("AuditPolicyChanges");
                match event.event_type.as_str() {
                    "windows.event_log.4625" => {
                        let stamp = system
                            .one("TimeCreated")?
                            .ok_or("invalid")?
                            .attrs
                            .get("SystemTime")
                            .ok_or("invalid")?;
                        let parsed = time::OffsetDateTime::parse(
                            stamp,
                            &time::format_description::well_known::Rfc3339,
                        )
                        .map_err(|_| "invalid")?;
                        if parsed.unix_timestamp_nanos() / 1_000_000
                            != i128::from(event.wall_clock_time)
                        {
                            return Err("invalid");
                        }
                        context.target_user = get("TargetUserName");
                        context.target_domain = get("TargetDomainName");
                        context.source_ip = get("IpAddress");
                        context.logon_type = get("LogonType");
                        context.caller_path = get("ProcessName");
                        context.failure_status = get("Status");
                        context.failure_sub_status = get("SubStatus");
                    }
                    "windows.event_log.4720" => {
                        context.target_user = get("TargetUserName");
                        context.target_domain = get("TargetDomainName");
                    }
                    "windows.event_log.4732" => {
                        context.group_name = get("TargetUserName");
                        context.group_sid = get("TargetSid");
                        context.member_sid = get("MemberSid");
                    }
                    "windows.event_log.4698" | "windows.event_log.4702" => {
                        context.task_name = get("TaskName");
                    }
                    "windows.event_log.1116" | "windows.event_log.1117" => {
                        context.threat_name = get("Threat Name");
                        context.resource_path = get("Path");
                        context.defender_action = get("Action Name");
                    }
                    "windows.event_log.5007" => {
                        context.old_value = get("Old Value");
                        context.new_value = get("New Value");
                    }
                    _ => {}
                }
            }
        }
        "windows.event_log.1102" | "windows.event_log.104" => {
            if tree.one("EventData")?.is_some() {
                return Err("invalid");
            }
            let user = tree.one("UserData")?.ok_or("invalid")?;
            let log = user.one("LogFileCleared")?.ok_or("invalid")?;
            if log.namespace != LOG_NS {
                return Err("invalid");
            }
            context.subject_user = log.text_of("SubjectUserName")?;
            context.subject_domain = log.text_of("SubjectDomainName")?;
            context.log_channel = if event.event_type == "windows.event_log.1102" {
                Some("Security".into())
            } else {
                log.text_of("Channel")?
            };
        }
        _ => return Err("invalid"),
    }
    Ok(context)
}

/// Named fields from a canonical Security-Auditing record. The Event Log emitter
/// PID is never read as an actor. Supports only explicitly reviewed versions.
pub(crate) fn authentication_fields(
    event: &SecurityEvent,
    raw: &RawEvidence,
) -> Result<BTreeMap<String, String>, &'static str> {
    event.validate().map_err(|_| "invalid")?;
    if event.sensor_id != "windows.event_log.Security"
        || event.event_category != "windows_event_log"
        || event.raw_evidence_reference != Some(raw.evidence_id)
        || raw.source != event.sensor_id
        || raw.content_type != "application/xml; charset=utf-8"
        || raw.bytes.len() > 192 * 1024
    {
        return Err("invalid");
    }
    let target = event.target.as_ref().ok_or("invalid")?;
    let record = target
        .identifier
        .strip_prefix("Security:Microsoft-Windows-Security-Auditing:")
        .ok_or("invalid")?;
    if target.kind != "windows_event_record" || record.parse::<u64>().ok().is_none_or(|id| id == 0)
    {
        return Err("invalid");
    }
    let tree = parse_xml(std::str::from_utf8(&raw.bytes).map_err(|_| "invalid")?)?;
    if tree.name != "Event" || tree.namespace != EVENT_NS || tree.one("UserData")?.is_some() {
        return Err("invalid");
    }
    let system = tree.one("System")?.ok_or("invalid")?;
    if system
        .one("Provider")?
        .ok_or("invalid")?
        .attrs
        .get("Name")
        .map(String::as_str)
        != Some("Microsoft-Windows-Security-Auditing")
        || system.text_of("Channel")?.as_deref() != Some("Security")
        || system.text_of("EventRecordID")?.as_deref() != Some(record)
        || format!(
            "windows.event_log.{}",
            system.text_of("EventID")?.ok_or("invalid")?
        ) != event.event_type
    {
        return Err("invalid");
    }
    let version = system.text_of("Version")?.ok_or("unsupported_version")?;
    let supported = match event.event_type.as_str() {
        // Version 3 reviewed against the installed ProviderMetadata template;
        // the named fields we use retain their v2 types. RemoteCredentialGuard
        // was added and is deliberately not interpreted here.
        "windows.event_log.4624" => ["0", "1", "2", "3"].contains(&version.as_str()),
        "windows.event_log.4625" | "windows.event_log.4648" | "windows.event_log.4672" => {
            version == "0"
        }
        _ => false,
    };
    if !supported {
        return Err("unsupported_version");
    }
    let stamp = system
        .one("TimeCreated")?
        .ok_or("invalid")?
        .attrs
        .get("SystemTime")
        .ok_or("invalid")?;
    let parsed = time::OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
        .map_err(|_| "invalid")?;
    if parsed.unix_timestamp_nanos() / 1_000_000 != i128::from(event.wall_clock_time) {
        return Err("invalid");
    }
    let data = tree.one("EventData")?.ok_or("invalid")?;
    let mut fields = BTreeMap::new();
    for field in &data.children {
        if field.name != "Data" || field.namespace != EVENT_NS || !field.children.is_empty() {
            return Err("invalid");
        }
        if fields
            .insert(
                field.attrs.get("Name").ok_or("invalid")?.clone(),
                field.text.trim().to_owned(),
            )
            .is_some()
        {
            return Err("invalid");
        }
    }
    if fields.len() > 256 {
        return Err("invalid");
    }
    Ok(fields)
}

#[derive(Debug)]
struct Node {
    name: String,
    namespace: String,
    attrs: BTreeMap<String, String>,
    children: Vec<Node>,
    text: String,
}

impl Node {
    fn one(&self, name: &str) -> Result<Option<&Node>, &'static str> {
        let mut matches = self.children.iter().filter(|child| child.name == name);
        let child = matches.next();
        if matches.next().is_some() {
            return Err("invalid");
        }
        Ok(child)
    }
    fn text_of(&self, name: &str) -> Result<Option<String>, &'static str> {
        self.one(name)?
            .map(|node| {
                if !node.children.is_empty() {
                    return Err("invalid");
                }
                Ok(node.text.trim().to_owned())
            })
            .transpose()
            .map(|text| text.filter(|text| !text.is_empty()))
    }
}

/// Accepts the canonical Windows XML namespace layout only. Unsupported prefix
/// layouts fail closed; DTDs/entities, duplicate fields/attributes, unexpected
/// namespaces, oversized text and deeply nested payloads never become names.
fn parse_xml(xml: &str) -> Result<Node, &'static str> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut nodes = 0;
    loop {
        let event = reader.read_event().map_err(|_| "invalid")?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                nodes += 1;
                if nodes > 256 || stack.len() > 8 {
                    return Err("invalid");
                }
                let name = tag.name().as_ref().to_owned();
                if name.contains(':') || name.len() > 128 {
                    return Err("invalid");
                }
                let mut namespace = stack
                    .last()
                    .map(|node| node.namespace.clone())
                    .unwrap_or_default();
                let mut attrs = BTreeMap::new();
                for attr in tag.attributes() {
                    let attr = attr.map_err(|_| "invalid")?;
                    let key = attr.key.as_ref();
                    let value = attr
                        .normalized_value(XmlVersion::Implicit1_0)
                        .map_err(|_| "invalid")?
                        .into_owned();
                    if key.len() > 128
                        || key.contains(':')
                        || value.len() > MAX_FIELD
                        || has_unsafe_controls(&value)
                    {
                        return Err("invalid");
                    }
                    if key == "xmlns" {
                        namespace = value.clone();
                    }
                    if attrs.insert(key.to_owned(), value).is_some() {
                        return Err("invalid");
                    }
                }
                let user_payload = stack.iter().any(|node| node.name == "LogFileCleared");
                let valid_namespace = if user_payload || name == "LogFileCleared" {
                    namespace == LOG_NS
                } else {
                    namespace == EVENT_NS
                };
                if !valid_namespace || (stack.is_empty() && root.is_some()) {
                    return Err("invalid");
                }
                let node = Node {
                    name,
                    namespace,
                    attrs,
                    children: Vec::new(),
                    text: String::new(),
                };
                if empty {
                    attach(&mut stack, &mut root, node)?;
                } else {
                    stack.push(node);
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or("invalid")?;
                attach(&mut stack, &mut root, node)?;
            }
            Event::Text(text) => {
                append_text(&mut stack, &text.xml_content(XmlVersion::Implicit1_0))?
            }
            Event::CData(text) => append_text(&mut stack, text.as_ref())?,
            Event::GeneralRef(reference) => {
                let encoded = format!("&{};", reference.as_ref());
                let decoded = quick_xml::escape::unescape(&encoded).map_err(|_| "invalid")?;
                append_text(&mut stack, &decoded)?;
            }
            Event::DocType(_) | Event::PI(_) => return Err("invalid"),
            Event::Decl(_) if root.is_none() && stack.is_empty() => {}
            Event::Comment(_) => {}
            Event::Eof => break,
            _ => return Err("invalid"),
        }
    }
    if !stack.is_empty() {
        return Err("invalid");
    }
    root.ok_or("invalid")
}

fn attach(stack: &mut [Node], root: &mut Option<Node>, node: Node) -> Result<(), &'static str> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return Err("invalid");
    }
    Ok(())
}

fn has_unsafe_controls(value: &str) -> bool {
    value.chars().any(|ch| {
        (ch.is_control() && !['\n', '\r', '\t'].contains(&ch))
            || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

fn append_text(stack: &mut [Node], value: &str) -> Result<(), &'static str> {
    if has_unsafe_controls(value) {
        return Err("invalid");
    }
    if let Some(node) = stack.last_mut() {
        let limit = if node.name == "Data"
            && node
                .attrs
                .get("Name")
                .is_some_and(|n| ["TaskContent", "TaskContentNew"].contains(&n.as_str()))
        {
            64 * 1024
        } else {
            MAX_FIELD
        };
        if node.text.len() + value.len() > limit {
            return Err("invalid");
        }
        node.text.push_str(value);
    } else if !value.trim().is_empty() {
        return Err("invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use piko_event_schema::{EventTarget, ProcessContext};
    use uuid::Uuid;

    fn fixture(event_id: u32, payload: &str) -> (SecurityEvent, RawEvidence) {
        let (channel, provider) = match event_id {
            7045 => ("System", "Service Control Manager"),
            104 => ("System", "Microsoft-Windows-Eventlog"),
            1102 => ("Security", "Microsoft-Windows-Eventlog"),
            4719 | 4720 | 4732 | 4698 | 4702 => ("Security", "Microsoft-Windows-Security-Auditing"),
            5001 | 5007 | 1116 | 1117 => (
                "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-Windows Defender",
            ),
            _ => panic!("unsupported test event"),
        };
        let mut event = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 100, 1);
        event.sensor_id = format!("windows.event_log.{channel}");
        event.event_category = "windows_event_log".into();
        event.event_type = format!("windows.event_log.{event_id}");
        event.target = Some(EventTarget {
            kind: "windows_event_record".into(),
            identifier: format!("{channel}:{provider}:42"),
        });
        let raw = RawEvidence {
            evidence_id: Uuid::new_v4(),
            source: event.sensor_id.clone(),
            content_type: "application/xml; charset=utf-8".into(),
            observed_at_unix_ms: event.observation_time,
            bytes: format!(r#"<Event xmlns="{EVENT_NS}"><System><Provider Name="{provider}"/><EventID>{event_id}</EventID><Version>0</Version><EventRecordID>42</EventRecordID><Execution ProcessID="888"/><Channel>{channel}</Channel></System>{payload}</Event>"#).into_bytes(),
        };
        event.raw_evidence_reference = Some(raw.evidence_id);
        (event, raw)
    }

    fn assessment(event: &SecurityEvent, raw: Option<&RawEvidence>) -> AlertAssessment {
        let mut alert = detect(event).expect("test event matches rule");
        assess(&mut alert, event, raw);
        let assessment = alert.assessment.expect("assessment");
        assert_eq!(assessment.model_version, "piko-risk-v1");
        assert_eq!(assessment.false_positive_probability, None);
        assert_eq!(
            assessment.risk_score,
            assessment
                .factors
                .iter()
                .map(|factor| factor.points)
                .sum::<i16>()
                .clamp(0, 100) as u8
        );
        assert_eq!(assessment.context.installer_process, None);
        assessment
    }

    fn replaced(raw: &RawEvidence, from: &str, to: &str) -> RawEvidence {
        let mut changed = raw.clone();
        let xml = std::str::from_utf8(&raw.bytes).expect("test XML");
        assert!(xml.contains(from), "fixture replacement must apply: {from}");
        changed.bytes = xml.replace(from, to).into_bytes();
        changed
    }

    #[test]
    fn names_come_from_service_evidence_not_the_emitter_process() {
        let (mut event, raw) = fixture(
            7045,
            r#"<EventData><Data Name="ServiceName">Backup &amp; Sync &#233;</Data><Data Name="ImagePath">&quot;C:\Users\Example\Backup App\backup.exe&quot; --quiet</Data><Data Name="AccountName">LocalSystem</Data></EventData>"#,
        );
        event.process = Some(ProcessContext {
            pid: 888,
            instance_id: None,
            name: Some("eventlog.exe".into()),
            executable_path: Some(r"C:\Windows\System32\eventlog.exe".into()),
            creation_time_unix_ms: None,
        });
        let result = assessment(&event, Some(&raw));
        assert_eq!(result.risk_score, 45);
        assert_eq!(result.context.evidence_status, "verified");
        assert_eq!(
            result.context.service_name.as_deref(),
            Some("Backup & Sync é")
        );
        assert_eq!(
            result.context.image_path.as_deref(),
            Some(r#""C:\Users\Example\Backup App\backup.exe" --quiet"#)
        );
        assert_eq!(
            result.context.service_account.as_deref(),
            Some("LocalSystem")
        );
        assert_eq!(result.context.subject_user, None);
    }

    #[test]
    fn account_and_cleared_channel_use_userdata_namespace() {
        for id in [104, 1102] {
            let (event, raw) = fixture(
                id,
                &format!(
                    r#"<UserData><LogFileCleared xmlns="{LOG_NS}"><SubjectUserName>Operator</SubjectUserName><SubjectDomainName>WORKSTATION</SubjectDomainName><Channel>Application</Channel></LogFileCleared></UserData>"#
                ),
            );
            let result = assessment(&event, Some(&raw));
            assert_eq!(result.risk_score, if id == 1102 { 70 } else { 50 });
            assert_eq!(result.context.subject_user.as_deref(), Some("Operator"));
            assert_eq!(
                result.context.subject_domain.as_deref(),
                Some("WORKSTATION")
            );
            assert_eq!(
                result.context.log_channel.as_deref(),
                Some(if id == 1102 {
                    "Security"
                } else {
                    "Application"
                })
            );
            let invalid = replaced(&raw, LOG_NS, "https://untrusted.example/namespace");
            assert_eq!(
                assessment(&event, Some(&invalid)).context.evidence_status,
                "invalid"
            );
        }
    }

    #[test]
    fn audit_score_distinguishes_removal_addition_and_unknown_changes() {
        // Source: Microsoft Azure-Sentinel/Tools/ParameterizedFunction/
        // AuditEventDataLookup_Func.ps1, and Microsoft event-4719 documentation.
        for (changes, score, factor) in [
            ("%%8448", 65, "audit_logging_removed"),
            ("%%8450", 65, "audit_logging_removed"),
            ("%%8449, %%8450", 65, "audit_logging_removed"),
            ("%%8449", 25, "audit_logging_added_only"),
            ("%%8451", 25, "audit_logging_added_only"),
            ("%%8449, %%8451", 25, "audit_logging_added_only"),
            ("localized text", 40, "audit_change_unknown"),
            ("%%8448, %%9999", 40, "audit_change_unknown"),
            ("", 40, "audit_change_unknown"),
        ] {
            let (event, raw) = fixture(
                4719,
                &format!(
                    r#"<EventData><Data Name="SubjectUserName">Admin</Data><Data Name="SubjectDomainName">PC</Data><Data Name="AuditPolicyChanges">{changes}</Data></EventData>"#
                ),
            );
            let result = assessment(&event, Some(&raw));
            assert_eq!(result.risk_score, score, "{changes}");
            assert!(result.factors.iter().any(|item| item.code == factor));
            assert_eq!(result.context.subject_user.as_deref(), Some("Admin"));
        }
    }

    #[test]
    fn evidence_is_bound_to_identity_source_record_and_supported_version() {
        let (event, raw) = fixture(
            7045,
            r#"<EventData><Data Name="ServiceName">Named service</Data><Data Name="ImagePath">C:\Windows\system32\service.exe</Data></EventData>"#,
        );
        let missing = assessment(&event, None);
        assert_eq!(missing.risk_score, 25);
        assert_eq!(missing.context.evidence_status, "missing");
        assert_eq!(missing.context.service_name, None);

        let mut wrong_id = raw.clone();
        wrong_id.evidence_id = Uuid::new_v4();
        let mut wrong_source = raw.clone();
        wrong_source.source = "windows.event_log.Application".into();
        let mut wrong_type = raw.clone();
        wrong_type.content_type = "text/plain".into();
        for invalid in [
            wrong_id,
            wrong_source,
            wrong_type,
            replaced(&raw, "Service Control Manager", "Untrusted provider"),
            replaced(&raw, "<Channel>System", "<Channel>Application"),
            replaced(&raw, "<EventRecordID>42", "<EventRecordID>43"),
            replaced(&raw, "<EventID>7045", "<EventID>7040"),
        ] {
            let result = assessment(&event, Some(&invalid));
            assert_eq!(result.risk_score, 25);
            assert_eq!(result.context.evidence_status, "invalid");
            assert_eq!(result.context.service_name, None);
            assert!(result
                .factors
                .iter()
                .any(|item| item.code == "evidence_invalid"));
        }
        let future = replaced(&raw, "<Version>0", "<Version>1");
        let result = assessment(&event, Some(&future));
        assert_eq!(result.context.evidence_status, "unsupported_version");
        assert_eq!(result.context.service_name, None);
        assert!(result
            .factors
            .iter()
            .any(|item| item.code == "evidence_version_unsupported"));
    }

    #[test]
    fn ambiguous_or_hostile_xml_never_becomes_a_display_name() {
        let (event, raw) = fixture(
            7045,
            r#"<EventData><Data Name="ServiceName">Example</Data><Data Name="ImagePath">C:\Windows\service.exe</Data></EventData>"#,
        );
        let original = std::str::from_utf8(&raw.bytes).expect("test XML");
        let changes = [
            original.replace(
                "<Event xmlns",
                "<!DOCTYPE Event [<!ENTITY x 'spoof'>]><Event xmlns",
            ),
            original.replace("Example", "&unknown;"),
            original.replace("Example", "&#x202E;spoof"),
            original.replace("Example", "&#0;spoof"),
            original.replace("Example", &"a".repeat(MAX_FIELD + 1)),
            original.replace("Example", "<Data>nested</Data>"),
            original.replace(
                "</EventData>",
                "<Data Name=\"ServiceName\">Duplicate</Data></EventData>",
            ),
            original.replace(
                "Name=\"ServiceName\"",
                "Name=\"ServiceName\" Name=\"ImagePath\"",
            ),
            original.replace(
                "<Version>0</Version>",
                "<Version>0</Version><Version>0</Version>",
            ),
            original.replace("</EventData>", "</EventData><EventData/>"),
            original.replace("</System>", "</System><System/>"),
            original.replace("</System>", "</EventData>"),
            original.replace(
                "<EventData>",
                "<EventData xmlns=\"https://untrusted.example\">",
            ),
            original.replace(
                "<EventData>",
                "<fake:EventData xmlns:fake=\"https://untrusted.example\">",
            ),
            format!("{original}{original}"),
            format!("{original}unexpected suffix"),
            original.replace(
                "Example",
                &format!("{}nested{}", "<Data>".repeat(10), "</Data>".repeat(10)),
            ),
            original.replace(
                "</EventData>",
                &format!("{}</EventData>", "<Data Name=\"x\"/>".repeat(257)),
            ),
            original.replace("Example", &"a".repeat(192 * 1024)),
        ];
        for (index, xml) in changes.into_iter().enumerate() {
            let mut invalid = raw.clone();
            invalid.bytes = xml.into_bytes();
            let result = assessment(&event, Some(&invalid));
            assert_eq!(result.context.evidence_status, "invalid", "case {index}");
            assert_eq!(result.context.service_name, None, "case {index}");
        }
    }

    #[test]
    fn path_indicator_uses_executable_part_and_is_only_a_heuristic() {
        for path in [
            r"C:\Users\Example\app.exe",
            r#""C:\Users\Example\App Name\app.exe" --run"#,
            r"%TEMP%\app.exe",
            r"%USERPROFILE%\app.exe",
            r"C:\Windows\Temp\app.exe",
            r"D:\Temp\app.exe",
            "c:/users/Example/app.exe",
        ] {
            assert!(untrusted_location(path), "{path}");
        }
        for path in [
            r#""C:\Program Files\Example\app.exe" --folder C:\Users\Example"#,
            r"C:\Windows\System32\service.exe C:\Users\Example\file",
            r"C:\UsersOther\app.exe",
            r"C:\Windows\Templates\app.exe",
            r#""C:\Users\Example\unclosed.exe"#,
            "",
        ] {
            assert!(!untrusted_location(path), "{path}");
        }
    }

    #[test]
    fn unrelated_rule_cannot_reuse_an_old_assessment() {
        let (event, raw) = fixture(7045, "<EventData/>");
        for mismatch in ["id", "rule", "version", "event", "evidence"] {
            let mut alert = detect(&event).expect("rule");
            assess(&mut alert, &event, Some(&raw));
            assert!(alert.assessment.is_some());
            match mismatch {
                "id" => alert.id = "other".into(),
                "rule" => alert.rule_id = "audit-log-cleared".into(),
                "version" => alert.rule_version = 2,
                "event" => alert.event_id = Uuid::new_v4(),
                "evidence" => alert.evidence_id = None,
                _ => unreachable!(),
            }
            assess(&mut alert, &event, Some(&raw));
            assert!(alert.assessment.is_none(), "{mismatch}");
        }
    }
    #[test]
    fn additional_rules_bind_names_to_raw_and_reject_source_spoofing() {
        for (id, fields, score) in [
            (
                4720,
                r#"<Data Name="TargetUserName">ExampleUser</Data><Data Name="SubjectUserName">operator</Data>"#,
                40,
            ),
            (
                4732,
                r#"<Data Name="TargetUserName">ExampleGroup</Data><Data Name="MemberSid">S-1-5-21-123</Data>"#,
                45,
            ),
            (4698, r#"<Data Name="TaskName">\ExampleTask</Data>"#, 35),
            (4702, r#"<Data Name="TaskName">\ExampleTask</Data>"#, 40),
            (5001, "", 75),
            (
                5007,
                r#"<Data Name="Old Value">old</Data><Data Name="New Value">new</Data>"#,
                25,
            ),
            (
                1116,
                r#"<Data Name="Threat Name">TestThreat</Data><Data Name="Path">file:_C:\Example.exe</Data>"#,
                80,
            ),
            (
                1117,
                r#"<Data Name="Threat Name">TestThreat</Data><Data Name="Action Name">Allow</Data>"#,
                45,
            ),
        ] {
            let (mut event, raw) = fixture(id, &format!("<EventData>{fields}</EventData>"));
            let result = assessment(&event, Some(&raw));
            assert_eq!(result.risk_score, score);
            assert_eq!(result.context.evidence_status, "verified");
            if id == 4720 {
                assert_eq!(result.context.target_user.as_deref(), Some("ExampleUser"));
            }
            if id == 1117 {
                assert_eq!(result.context.defender_action.as_deref(), Some("Allow"));
            }
            let changed = replaced(
                &raw,
                "<EventRecordID>42</EventRecordID>",
                "<EventRecordID>43</EventRecordID>",
            );
            assert_eq!(
                assessment(&event, Some(&changed)).context.evidence_status,
                "invalid"
            );
            event.target.as_mut().expect("test target").identifier =
                "Application:UnknownProvider:42".into();
            assert!(detect(&event).is_none());
        }
    }
    #[test]
    fn task_v1_large_embedded_definition_is_raw_only_and_future_version_is_unknown() {
        let payload = format!(
            r#"<EventData><Data Name="TaskName">\ExampleTask</Data><Data Name="TaskContent">{}</Data></EventData>"#,
            "x".repeat(6000)
        );
        let (event, raw) = fixture(4698, &payload);
        let raw = replaced(&raw, "<Version>0</Version>", "<Version>1</Version>");
        let result = assessment(&event, Some(&raw));
        assert_eq!(result.context.task_name.as_deref(), Some(r"\ExampleTask"));
        assert_eq!(result.context.installer_process, None);
        let future = replaced(&raw, "<Version>1</Version>", "<Version>2</Version>");
        assert_eq!(
            assessment(&event, Some(&future)).context.evidence_status,
            "unsupported_version"
        );
    }
}
