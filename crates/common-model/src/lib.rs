#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Observed runtime health. This is not a claim of endpoint protection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthSnapshot {
    pub product: String,
    pub version: String,
    pub protection_state: String,
    pub runtime_mode: String,
    pub uptime_seconds: u64,
    pub stored_events: u64,
    pub queue_depth: usize,
    pub dropped_events: u64,
    pub sensors: Vec<SensorHealth>,
    #[serde(default)]
    pub performance: Option<RuntimePerformance>,
    #[serde(default)]
    pub performance_error: Option<String>,
    #[serde(default)]
    pub archive: Option<ArchiveUsage>,
    #[serde(default)]
    pub archive_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SensorHealth {
    pub id: String,
    pub state: String,
    pub detail: String,
    pub last_seen_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedProcess {
    pub instance_id: Option<String>,
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub executable: Option<String>,
    /// Native 100ns precision retained for identity. Never use rounded milliseconds as the key.
    #[serde(with = "optional_decimal")]
    pub creation_filetime: Option<u64>,
    pub sid: Option<String>,
    pub session_id: Option<u32>,
    pub access_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedConnection {
    pub pid: u32,
    /// Present only when the same process exists before AND after the table read.
    #[serde(with = "optional_decimal")]
    pub process_creation_filetime: Option<u64>,
    pub family: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: u32,
}

/// A local UDP bind observation; contains no remote destination or traffic assertion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedUdpEndpoint {
    pub pid: u32,
    #[serde(with = "optional_decimal")]
    pub process_creation_filetime: Option<u64>,
    pub family: String,
    pub local_address: String,
    pub local_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    pub started_at_unix_ms: i64,
    pub completed_at_unix_ms: i64,
    pub processes: Vec<ObservedProcess>,
    pub connections: Vec<ObservedConnection>,
    #[serde(default)]
    pub udp_endpoints: Vec<ObservedUdpEndpoint>,
    #[serde(default)]
    pub udp_complete: Option<bool>,
    pub process_complete: bool,
    pub network_complete: bool,
    pub warnings: Vec<String>,
}

// Exact Windows 100ns ticks exceed JavaScript's safe integer range.
mod optional_decimal {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|v| v.to_string()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimePerformance {
    pub sampled_at_unix_ms: i64,
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub cpu_percent_x100: Option<u16>,
    pub interval_ms: u64,
    pub logical_processors: Option<u32>,
}

/// Current archive footprint, sampled by its storage worker; not retention or free volume space.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveUsage {
    pub sampled_at_unix_ms: i64,
    pub budget_bytes: u64,
    pub database_limit_bytes: u64,
    pub database_bytes: u64,
    /// Logical pages in use; includes committed WAL state and excludes reusable pages.
    #[serde(default)]
    pub database_active_bytes: Option<u64>,
    #[serde(default)]
    pub retention_months: Option<u8>,
    #[serde(default)]
    pub expired_events: u64,
    pub total_bytes: u64,
}
