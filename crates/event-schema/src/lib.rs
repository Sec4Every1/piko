#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_EVENT_BYTES: usize = 256 * 1024;
pub const MAX_RAW_EVIDENCE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityContext {
    pub sid: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessContext {
    pub pid: u32,
    /// A PID is reusable; this field is absent until a sensor observes identity.
    pub instance_id: Option<Uuid>,
    pub name: Option<String>,
    pub executable_path: Option<String>,
    pub creation_time_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventTarget {
    pub kind: String,
    pub identifier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntegrityMetadata {
    pub normalization_version: u32,
    /// Source-supplied integrity evidence, never an inferred trust verdict.
    pub source_integrity: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub schema_version: u32,
    pub event_id: Uuid,
    pub host_id: Uuid,
    /// Unknown in the foundation slice; a runtime restart is not a Windows boot.
    pub boot_id: Option<Uuid>,
    pub runtime_instance_id: Uuid,
    pub sensor_id: String,
    pub sequence: u64,
    /// UTC milliseconds since Unix epoch. These fields never define ordering.
    pub wall_clock_time: i64,
    /// Nanoseconds since this runtime's Instant origin, not since Windows boot.
    pub monotonic_time: u64,
    pub observation_time: i64,
    pub ingestion_time: i64,
    pub event_category: String,
    pub event_type: String,
    pub severity: Severity,
    pub actor_identity: Option<IdentityContext>,
    pub logon_session: Option<String>,
    pub process: Option<ProcessContext>,
    pub parent_process: Option<ProcessContext>,
    pub target: Option<EventTarget>,
    pub operation: String,
    pub result: String,
    pub causal_parents: Vec<Uuid>,
    pub correlation_ids: Vec<Uuid>,
    pub raw_evidence_reference: Option<Uuid>,
    pub integrity_metadata: IntegrityMetadata,
}

impl SecurityEvent {
    /// Describes the running process only; does not fabricate system telemetry.
    pub fn heartbeat(
        host_id: Uuid,
        runtime_instance_id: Uuid,
        sequence: u64,
        wall_unix_ms: i64,
        monotonic_ns: u64,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::new_v4(),
            host_id,
            boot_id: None,
            runtime_instance_id,
            sensor_id: "piko.runtime".into(),
            sequence,
            wall_clock_time: wall_unix_ms,
            monotonic_time: monotonic_ns,
            observation_time: wall_unix_ms,
            ingestion_time: wall_unix_ms,
            event_category: "sensor_health".into(),
            event_type: "runtime.heartbeat".into(),
            severity: Severity::Info,
            actor_identity: None,
            logon_session: None,
            process: Some(ProcessContext {
                pid: std::process::id(),
                instance_id: Some(runtime_instance_id),
                name: None,
                executable_path: None,
                creation_time_unix_ms: None,
            }),
            parent_process: None,
            target: None,
            operation: "heartbeat".into(),
            result: "observed".into(),
            causal_parents: Vec::new(),
            correlation_ids: Vec::new(),
            raw_evidence_reference: None,
            integrity_metadata: IntegrityMetadata {
                normalization_version: 1,
                source_integrity: None,
            },
        }
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SchemaError::UnsupportedVersion(self.schema_version));
        }
        if self.event_id.is_nil() || self.host_id.is_nil() || self.runtime_instance_id.is_nil() {
            return Err(SchemaError::InvalidField("nil identity"));
        }
        if self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err(SchemaError::InvalidField("sequence"));
        }
        if self.wall_clock_time < 0 || self.observation_time < 0 || self.ingestion_time < 0 {
            return Err(SchemaError::InvalidField("timestamp"));
        }
        for value in [
            &self.sensor_id,
            &self.event_category,
            &self.event_type,
            &self.operation,
            &self.result,
        ] {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return Err(SchemaError::InvalidField("event label"));
            }
        }
        if self.causal_parents.len() > 128 || self.correlation_ids.len() > 128 {
            return Err(SchemaError::InvalidField("reference count"));
        }
        if self.causal_parents.contains(&self.event_id) {
            return Err(SchemaError::InvalidField("self causal reference"));
        }
        // Count encoded bytes without allocating an unbounded serialization.
        let mut size = BoundedSize { bytes: 0 };
        if let Err(error) = serde_json::to_writer(&mut size, self) {
            if size.bytes > MAX_EVENT_BYTES {
                return Err(SchemaError::TooLarge);
            }
            return Err(error.into());
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(SchemaError::TooLarge);
        }
        let event: Self = serde_json::from_slice(bytes)?;
        event.validate()?;
        Ok(event)
    }
}

struct BoundedSize {
    bytes: usize,
}

impl Write for BoundedSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > MAX_EVENT_BYTES {
            return Err(io::Error::other("event size limit"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawEvidence {
    pub evidence_id: Uuid,
    pub source: String,
    pub content_type: String,
    pub observed_at_unix_ms: i64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub event: SecurityEvent,
    pub raw_evidence: Option<RawEvidence>,
}

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("unsupported event schema version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid event field: {0}")]
    InvalidField(&'static str),
    #[error("event exceeds the size limit")]
    TooLarge,
    #[error("invalid event JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_unknown_values_without_inventing_boot() {
        let event = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 500, 5);
        let json = serde_json::to_vec(&event).expect("serialize");
        assert_eq!(SecurityEvent::decode(&json).expect("decode"), event);
        assert!(event.boot_id.is_none());
        assert!(event.actor_identity.is_none());
    }

    #[test]
    fn rejects_versions_oversize_and_invalid_ordering_identity() {
        let mut event = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 500, 5);
        event.schema_version = 99;
        assert!(matches!(
            event.validate(),
            Err(SchemaError::UnsupportedVersion(99))
        ));
        event.schema_version = 1;
        event.sequence = 0;
        assert!(event.validate().is_err());
        assert!(matches!(
            SecurityEvent::decode(&vec![b' '; MAX_EVENT_BYTES + 1]),
            Err(SchemaError::TooLarge)
        ));
    }

    #[test]
    fn unknown_fields_and_self_causality_are_rejected() {
        let mut event = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 500, 5);
        event.causal_parents.push(event.event_id);
        assert!(event.validate().is_err());
        event.causal_parents.clear();
        let mut json = serde_json::to_value(event).expect("serialize");
        json["unexpected"] = serde_json::json!(true);
        assert!(SecurityEvent::decode(&serde_json::to_vec(&json).expect("serialize")).is_err());
    }
}
