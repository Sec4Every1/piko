//! Safe ETW normalization and bounded orchestration; all native pointers stay in
//! win-platform. Continuous events complement snapshots without fabricating an
//! actor, process lifetime identity, or causality from the ETW header PID.
use piko_common_model::{ObservedProcess, SensorHealth};
use piko_event_schema::{
    EventRecord, EventTarget, ProcessContext, RawEvidence, SecurityEvent, Severity,
};
use piko_win_platform::etw::{EtwRecord, EtwSession, EtwStatistics, MAX_RECORD_BYTES, PROVIDER_ID};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

pub const ETW_SENSOR_ID: &str = "windows.etw.process_image";
// Image loads arrive in bursts when an application starts. 256 bounded records
// reserve at most 16 MiB of raw payload; sustained overload still counts loss.
pub const ETW_FORWARD_CAPACITY: usize = 256;
pub struct EtwCollector {
    pub records: mpsc::Receiver<EtwRecord>,
    pub health: watch::Receiver<SensorHealth>,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl EtwCollector {
    /// No privilege escalation or fallback session. Permission errors are
    /// published as degraded health while the ordinary snapshot sensor continues.
    pub fn start() -> io::Result<Self> {
        let (sender, records) = mpsc::channel(ETW_FORWARD_CAPACITY);
        let initial = SensorHealth {
            id: ETW_SENSOR_ID.into(),
            state: "starting".into(),
            detail: "Opening bounded real-time process/image ETW session".into(),
            last_seen_unix_ms: None,
        };
        let (health_sender, health) = watch::channel(initial);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let worker = std::thread::Builder::new().name("piko-etw-collector".into()).spawn(move || {
            if stop.load(Ordering::Acquire) { return; }
            let mut session = match EtwSession::start() {
                Ok(session) => session,
                Err(error) => {
                    health_sender.send_replace(SensorHealth { id: ETW_SENSOR_ID.into(), state: "degraded".into(), detail: format!("ETW unavailable: {error}. Standard tokens may lack trace permissions; no account, privilege, driver or audit policy was changed. Process/TCP snapshots remain separate."), last_seen_unix_ms: None });
                    return;
                }
            };
            let mut forwarded_dropped = 0u64;
            let mut last_statistics = Instant::now() - Duration::from_secs(2);
            while !stop.load(Ordering::Acquire) && !sender.is_closed() {
                match session.poll(Duration::from_millis(100)) {
                    Ok(Some(record)) => {
                        // ETW has no durable bookmark/replay. Never block its consumer
                        // behind SQLite: expose any bounded-queue loss in health.
                        match sender.try_send(record) {
                            Ok(()) => {},
                            Err(mpsc::error::TrySendError::Full(_)) => forwarded_dropped = forwarded_dropped.saturating_add(1),
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    Ok(None) => {},
                    Err(error) => {
                        let last_seen_unix_ms = health_sender.borrow().last_seen_unix_ms;
                        health_sender.send_replace(SensorHealth { id: ETW_SENSOR_ID.into(), state: "degraded".into(), detail: format!("ETW consumer stopped: {error}; continuous process/image coverage is unavailable"), last_seen_unix_ms });
                        break;
                    }
                }
                if last_statistics.elapsed() >= Duration::from_secs(2) {
                    match session.statistics() {
                        Ok(statistics) => { health_sender.send_replace(statistics_health(&statistics, forwarded_dropped)); },
                        Err(error) => {
                            let last_seen_unix_ms = health_sender.borrow().last_seen_unix_ms;
                            health_sender.send_replace(SensorHealth { id: ETW_SENSOR_ID.into(), state: "degraded".into(), detail: format!("ETW session statistics unavailable: {error}; loss/availability cannot be verified"), last_seen_unix_ms });
                        }
                    }
                    last_statistics = Instant::now();
                }
            }
            if let Err(error) = session.stop() {
                let last_seen_unix_ms = health_sender.borrow().last_seen_unix_ms;
                health_sender.send_replace(SensorHealth { id: ETW_SENSOR_ID.into(), state: "degraded".into(), detail: format!("ETW owned-session cleanup: {error}"), last_seen_unix_ms });
            }
        })?;
        Ok(Self {
            records,
            health,
            stopped,
            worker: Some(worker),
        })
    }
    pub fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.records.close();
        // Native session Stop/Close happens before runtime shutdown where possible.
        // A slow OS call retains its worker-owned context safely; no unbounded join.
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(6);
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}
impl Drop for EtwCollector {
    fn drop(&mut self) {
        self.stop();
    }
}

fn statistics_health(s: &EtwStatistics, forwarded_dropped: u64) -> SensorHealth {
    let lost = s.queue_dropped != 0
        || forwarded_dropped != 0
        || s.events_lost != 0
        || s.real_time_buffers_lost != 0
        || s.malformed != 0
        || s.decode_failures != 0;
    let state = if !s.running || s.processing_error.is_some() || lost {
        "degraded"
    } else if s.received == 0 {
        "limited"
    } else {
        "active"
    };
    SensorHealth {
        id: ETW_SENSOR_ID.into(), state: state.into(), last_seen_unix_ms: s.last_seen_unix_ms,
        detail: format!("Real-time manifest process/image ETW; {} received; {} native queue drops; {} forwarding drops; {} malformed; {} TDH decode failures; {} ETW events lost; {} real-time buffers lost. ProcessTrace running: {}; error: {:?}. Coverage: process start/stop and image loads; image unloads excluded by security-noise.v1. No replay or pre-start history; PPID is not proven causality; events are not malware verdicts.", s.received, s.queue_dropped, forwarded_dropped, s.malformed, s.decode_failures, s.events_lost, s.real_time_buffers_lost, s.running, s.processing_error),
    }
}

/// Caller supplies ingestion/runtime identity and a positive sequence. The
/// heartbeat template's own process/identity is always cleared before reuse.
pub fn normalize_etw(record: EtwRecord, mut event: SecurityEvent) -> io::Result<EventRecord> {
    if record.provider_id != PROVIDER_ID
        || record.activity_id.len() != 36
        || Uuid::parse_str(&record.activity_id).is_err()
        || record
            .decode_error
            .as_ref()
            .is_some_and(|error| error.len() > 4096)
        || record.payload.len().saturating_add(
            record
                .extended_data
                .iter()
                .map(|item| item.bytes.len())
                .sum::<usize>(),
        ) > MAX_RECORD_BYTES
        || record.extended_data.len() > 32
        || record.observed_at_unix_ms < 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or oversized ETW source record",
        ));
    }
    if record
        .fields
        .image_name
        .as_ref()
        .is_some_and(|name| name.len() > 4096 || name.chars().any(char::is_control))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW image name",
        ));
    }
    let classification = match (record.event_id, record.task, record.opcode) {
        (1, 1, 1) if record.keyword & 0x10 != 0 => {
            Some(("process", "process.etw.started", "start_process"))
        }
        (2, 2, 2) if record.keyword & 0x10 != 0 => {
            Some(("process", "process.etw.stopped", "stop_process"))
        }
        (5, 5, 0) if record.keyword & 0x40 != 0 => {
            Some(("image", "image.etw.loaded", "load_image"))
        }
        (6, 6, 0) if record.keyword & 0x40 != 0 => {
            Some(("image", "image.etw.unloaded", "unload_image"))
        }
        _ => None,
    };
    let (category, event_type, operation) =
        classification.unwrap_or(("telemetry", "etw.unclassified", "observe_etw"));
    let fields_valid = record.decode_error.is_none()
        && classification.is_some()
        && record.fields.process_id.is_some();
    let process_image = category == "process";
    event.sensor_id = ETW_SENSOR_ID.into();
    event.event_category = category.into();
    event.event_type = event_type.into();
    event.operation = operation.into();
    event.result = if fields_valid {
        "observed"
    } else {
        "observed_raw"
    }
    .into();
    event.severity = Severity::Info;
    event.wall_clock_time = piko_win_platform::observations::filetime_unix_ms(
        record.timestamp_filetime,
    )
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ETW timestamp outside supported UTC epoch",
        )
    })?;
    event.observation_time = record.observed_at_unix_ms;
    event.actor_identity = None;
    event.logon_session = None;
    event.process = None;
    event.parent_process = None;
    event.target = None;
    event.causal_parents.clear();
    event.correlation_ids.clear();
    event.integrity_metadata.source_integrity = None;
    if fields_valid {
        event.process = record.fields.process_id.map(|pid| {
            let name = process_image
                .then(|| record.fields.image_name.clone())
                .flatten();
            let creation_filetime = record
                .fields
                .creation_filetime
                .filter(|time| piko_win_platform::observations::filetime_unix_ms(*time).is_some());
            let observed = ObservedProcess {
                instance_id: None,
                pid,
                parent_pid: 0,
                name: String::new(),
                executable: None,
                creation_filetime,
                sid: None,
                session_id: None,
                access_error: None,
            };
            ProcessContext {
                pid,
                instance_id: super::process_instance(event.host_id, &observed),
                name: name
                    .as_ref()
                    .map(|name| name.rsplit(['\\', '/']).next().unwrap_or(name).to_owned()),
                executable_path: name.filter(|name| absolute_windows_path(name)),
                creation_time_unix_ms: record
                    .fields
                    .creation_filetime
                    .and_then(piko_win_platform::observations::filetime_unix_ms),
            }
        });
        if record.event_id == 1 {
            event.parent_process =
                record
                    .fields
                    .parent_process_id
                    .filter(|pid| *pid != 0)
                    .map(|pid| ProcessContext {
                        pid,
                        instance_id: None,
                        name: None,
                        executable_path: None,
                        creation_time_unix_ms: None,
                    });
        }
        if !process_image {
            event.target = record.fields.image_name.as_ref().map(|path| EventTarget {
                kind: "loaded_image".into(),
                identifier: path.clone(),
            });
        }
    }
    let evidence_id = Uuid::new_v4();
    event.raw_evidence_reference = Some(evidence_id);
    let raw = serde_json::json!({
        "schema": "piko.etw.record.v1",
        "provider": "Microsoft-Windows-Kernel-Process", "provider_id": record.provider_id,
        "descriptor": { "id": record.event_id, "version": record.version, "opcode": record.opcode, "task": record.task, "keyword_hex": format!("0x{:016x}", record.keyword), "level": record.level },
        "header": { "flags": record.flags, "process_id": record.header_process_id, "thread_id": record.header_thread_id, "activity_id": record.activity_id, "timestamp_filetime": record.timestamp_filetime.to_string() },
        "observed_at_unix_ms": record.observed_at_unix_ms,
        "payload_hex": hex(&record.payload),
        "extended_data": record.extended_data.iter().map(|item| serde_json::json!({ "kind": item.kind, "data_hex": hex(&item.bytes) })).collect::<Vec<_>>(),
        "tdh_fields": { "process_id": record.fields.process_id, "parent_process_id": record.fields.parent_process_id, "creation_filetime": record.fields.creation_filetime.map(|value| value.to_string()), "image_name": record.fields.image_name, "session_id": record.fields.session_id },
        "decode_error": record.decode_error,
        "semantics": "ETW manifest event copied during native callback, not an ETL file; header PID identifies event producer context and is not substituted for payload ProcessID; image events name the loaded image, not the executable; ANSI image names are shown only if ASCII because no source codepage is supplied; PPID has no verified parent instance/causality; no logon LUID inferred; no pre-start replay"
    });
    event.validate().map_err(io::Error::other)?;
    Ok(EventRecord {
        event,
        raw_evidence: Some(RawEvidence {
            evidence_id,
            source: ETW_SENSOR_ID.into(),
            content_type: "application/json".into(),
            observed_at_unix_ms: record.observed_at_unix_ms,
            bytes: serde_json::to_vec(&raw).map_err(io::Error::other)?,
        }),
    })
}
fn absolute_windows_path(value: &str) -> bool {
    value.starts_with('\\')
        || (value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .get(2)
                .is_some_and(|b| *b == b'\\' || *b == b'/'))
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[(byte >> 4) as usize]));
        output.push(char::from(DIGITS[(byte & 15) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use piko_win_platform::etw::{EtwFields, ExtendedData};
    fn record(id: u16) -> EtwRecord {
        EtwRecord {
            provider_id: PROVIDER_ID.into(),
            event_id: id,
            version: 4,
            opcode: if id == 1 { 1 } else { 0 },
            task: id,
            keyword: if id == 1 { 0x10 } else { 0x40 },
            level: 4,
            flags: 0,
            header_process_id: 999,
            header_thread_id: 1000,
            activity_id: Uuid::nil().to_string(),
            timestamp_filetime: 133_000_000_000_000_001,
            observed_at_unix_ms: 1_655_526_400_001,
            payload: vec![0, 0xff, 0x42],
            extended_data: vec![ExtendedData {
                kind: 13,
                bytes: vec![1, 2, 3],
            }],
            fields: EtwFields {
                process_id: Some(42),
                parent_process_id: Some(7),
                creation_filetime: Some(133_000_000_000_000_001),
                image_name: Some("C:\\app\\example.exe".into()),
                session_id: Some(2),
            },
            decode_error: None,
        }
    }
    fn template() -> SecurityEvent {
        SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 1_655_526_400_002, 1)
    }
    #[test]
    fn process_fixture_has_payload_identity_and_preserves_raw_without_invented_actor(
    ) -> io::Result<()> {
        let event = normalize_etw(record(1), template())?;
        let process = event
            .event
            .process
            .as_ref()
            .ok_or_else(|| io::Error::other("process missing"))?;
        assert_eq!(process.pid, 42);
        assert_eq!(process.name.as_deref(), Some("example.exe"));
        assert!(process.instance_id.is_some());
        assert_eq!(event.event.parent_process.as_ref().map(|p| p.pid), Some(7));
        assert!(event
            .event
            .parent_process
            .as_ref()
            .is_some_and(|p| p.instance_id.is_none()));
        assert!(event.event.actor_identity.is_none());
        assert!(event.event.logon_session.is_none());
        assert!(event.event.causal_parents.is_empty());
        let raw = event
            .raw_evidence
            .ok_or_else(|| io::Error::other("raw missing"))?;
        let json: serde_json::Value =
            serde_json::from_slice(&raw.bytes).map_err(io::Error::other)?;
        assert_eq!(json["payload_hex"], "00ff42");
        assert_eq!(json["header"]["process_id"], 999);
        assert_eq!(
            json["tdh_fields"]["creation_filetime"],
            "133000000000000001"
        );
        Ok(())
    }
    #[test]
    fn image_name_never_becomes_process_name_and_undecodable_or_changed_descriptor_stays_raw(
    ) -> io::Result<()> {
        let mut image = record(5);
        image.fields.creation_filetime = None;
        image.fields.image_name = Some("C:\\app\\module.dll".into());
        let normalized = normalize_etw(image.clone(), template())?;
        assert_eq!(normalized.event.event_type, "image.etw.loaded");
        assert!(normalized
            .event
            .process
            .as_ref()
            .is_some_and(|p| p.name.is_none()
                && p.executable_path.is_none()
                && p.instance_id.is_none()));
        assert_eq!(
            normalized
                .event
                .target
                .as_ref()
                .map(|t| t.identifier.as_str()),
            Some("C:\\app\\module.dll")
        );
        image.decode_error = Some("unknown TDH schema".into());
        let undecoded = normalize_etw(image.clone(), template())?;
        assert!(undecoded.event.process.is_none());
        assert_eq!(undecoded.event.result, "observed_raw");
        image.decode_error = None;
        image.opcode = 99;
        let changed = normalize_etw(image, template())?;
        assert_eq!(changed.event.event_type, "etw.unclassified");
        assert!(changed.event.process.is_none());
        Ok(())
    }
    #[test]
    fn pid_reuse_submillisecond_identity_and_loss_health_are_explicit() -> io::Result<()> {
        let base = template();
        let first = normalize_etw(record(1), base.clone())?;
        let mut other = record(1);
        other.fields.creation_filetime = Some(133_000_000_000_000_002);
        let second = normalize_etw(other, base)?;
        assert_ne!(
            first.event.process.map(|p| p.instance_id),
            second.event.process.map(|p| p.instance_id)
        );
        let s = EtwStatistics {
            running: true,
            received: 2,
            ..Default::default()
        };
        assert_eq!(statistics_health(&s, 0).state, "active");
        assert_eq!(statistics_health(&s, 1).state, "degraded");
        assert_eq!(
            statistics_health(
                &EtwStatistics {
                    running: true,
                    ..Default::default()
                },
                0
            )
            .state,
            "limited"
        );
        let mut too_big = record(1);
        too_big.payload = vec![0; MAX_RECORD_BYTES];
        assert!(normalize_etw(too_big, template()).is_err());
        let mut malformed = record(1);
        malformed.activity_id = "not-a-source-guid".into();
        assert!(normalize_etw(malformed, template()).is_err());
        Ok(())
    }
}
