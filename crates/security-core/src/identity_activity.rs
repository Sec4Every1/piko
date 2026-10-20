//! Evidence-backed authentication facts, never a compromise or elevation verdict.
use crate::assessment::authentication_fields;
use piko_event_schema::{RawEvidence, SecurityEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationKind {
    SuccessfulLogon,
    FailedLogon,
    ExplicitCredentials,
    SpecialPrivileges,
    AccountCreated,
    AccountEnabled,
    AccountDisabled,
    AccountDeleted,
}
impl AuthenticationKind {
    pub fn event_type(self) -> &'static str {
        match self {
            Self::SuccessfulLogon => "windows.event_log.4624",
            Self::FailedLogon => "windows.event_log.4625",
            Self::ExplicitCredentials => "windows.event_log.4648",
            Self::SpecialPrivileges => "windows.event_log.4672",
            Self::AccountCreated => "windows.event_log.4720",
            Self::AccountEnabled => "windows.event_log.4722",
            Self::AccountDisabled => "windows.event_log.4725",
            Self::AccountDeleted => "windows.event_log.4726",
        }
    }
    pub fn from_event_type(value: &str) -> Option<Self> {
        [
            Self::SuccessfulLogon,
            Self::FailedLogon,
            Self::ExplicitCredentials,
            Self::SpecialPrivileges,
            Self::AccountCreated,
            Self::AccountEnabled,
            Self::AccountDisabled,
            Self::AccountDeleted,
        ]
        .into_iter()
        .find(|kind| kind.event_type() == value)
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationIdentity {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub sid: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationContext {
    pub evidence_status: String,
    pub account: AuthenticationIdentity,
    pub subject: AuthenticationIdentity,
    pub logon_type: Option<u32>,
    pub logon_id: Option<String>,
    /// A source-supplied address, not an assertion about an attacker or route.
    pub address: Option<String>,
    pub workstation: Option<String>,
    pub caller_path: Option<String>,
    pub caller_pid: Option<u32>,
    pub target_server: Option<String>,
    pub authentication_package: Option<String>,
    pub privileges: Vec<String>,
}
pub fn authentication_context(
    event: &SecurityEvent,
    raw: Option<&RawEvidence>,
) -> AuthenticationContext {
    let fields = match raw {
        None => {
            return AuthenticationContext {
                evidence_status: "missing".into(),
                ..Default::default()
            }
        }
        Some(raw) => match authentication_fields(event, raw) {
            Ok(fields) => fields,
            Err(status) => {
                return AuthenticationContext {
                    evidence_status: status.into(),
                    ..Default::default()
                }
            }
        },
    };
    let get = |key: &str| {
        fields
            .get(key)
            .filter(|value| {
                !value.is_empty() && value.as_str() != "-" && !value.chars().any(char::is_control)
            })
            .cloned()
    };
    let management = matches!(
        AuthenticationKind::from_event_type(&event.event_type),
        Some(
            AuthenticationKind::AccountCreated
                | AuthenticationKind::AccountEnabled
                | AuthenticationKind::AccountDisabled
                | AuthenticationKind::AccountDeleted
        )
    );
    let identity = |prefix: &str| AuthenticationIdentity {
        name: get(&format!("{prefix}UserName")),
        domain: get(&format!("{prefix}DomainName")),
        sid: get(&if management && prefix == "Target" {
            "TargetSid".into()
        } else {
            format!("{prefix}UserSid")
        })
        .filter(|value| {
            value.starts_with("S-1-")
                && value != "S-1-0-0"
                && value.len() <= 184
                && value[4..]
                    .split('-')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        }),
    };
    let special = event.event_type == "windows.event_log.4672";
    let explicit = event.event_type == "windows.event_log.4648";
    let logon = get(if event.event_type == "windows.event_log.4624" {
        "TargetLogonId"
    } else {
        "SubjectLogonId"
    });
    let privileges = if special {
        privilege_list(&fields)
    } else {
        Vec::new()
    };
    let mut account = identity(if special { "Subject" } else { "Target" });
    if explicit {
        account.sid = None;
    }
    AuthenticationContext {
        evidence_status: "verified".into(),
        account,
        subject: identity("Subject"),
        logon_type: if special || explicit || management {
            None
        } else {
            get("LogonType").and_then(|v| v.parse().ok())
        },
        logon_id: logon
            .as_deref()
            .and_then(hex_number)
            .filter(|n| *n != 0)
            .map(|n| format!("0x{n:x}")),
        address: (!special && !management)
            .then(|| get("IpAddress"))
            .flatten()
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
            .map(|v| v.to_string()),
        workstation: if special || explicit || management {
            None
        } else {
            get("WorkstationName")
        },
        caller_path: (!special && !management)
            .then(|| get("ProcessName"))
            .flatten(),
        caller_pid: (!special && !management)
            .then(|| get("ProcessId"))
            .flatten()
            .as_deref()
            .and_then(hex_number)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|n| *n != 0),
        target_server: if explicit {
            get("TargetServerName")
        } else {
            None
        },
        authentication_package: if special || explicit || management {
            None
        } else {
            get("AuthenticationPackageName")
        },
        privileges,
    }
}
fn hex_number(value: &str) -> Option<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}
fn privilege_list(fields: &BTreeMap<String, String>) -> Vec<String> {
    let Some(value) = fields.get("PrivilegeList") else {
        return Vec::new();
    };
    let tokens: Vec<_> = value.split_whitespace().collect();
    if tokens.len() > 64
        || tokens
            .iter()
            .any(|v| v.len() > 128 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Vec::new();
    }
    tokens.into_iter().map(str::to_owned).collect()
}
