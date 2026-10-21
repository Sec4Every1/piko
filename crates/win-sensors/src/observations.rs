//! Bounded polling telemetry. Observed changes are never reported as kernel events.
use piko_common_model::{
    ObservationSnapshot, ObservedConnection, ObservedProcess, ObservedUdpEndpoint, SensorHealth,
};
use piko_event_schema::{
    EventRecord, EventTarget, IdentityContext, ProcessContext, RawEvidence, SecurityEvent, Severity,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

pub struct ObservationCollector {
    pub records: mpsc::Receiver<Observation>,
    pub latest: watch::Receiver<Option<ObservationSnapshot>>,
    pub health: watch::Receiver<SensorHealth>,
    stopped: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub transition: &'static str,
    pub at: i64,
    pub process: Option<ObservedProcess>,
    /// Same-snapshot parent lifetime, never resolved from a PID alone.
    pub parent: Option<ObservedProcess>,
    pub connection: Option<ObservedConnection>,
    pub udp: Option<ObservedUdpEndpoint>,
}

#[derive(Default)]
struct History {
    processes: BTreeMap<String, ObservedProcess>,
    parents: BTreeMap<String, ObservedProcess>,
    connections: BTreeMap<String, (ObservedConnection, Option<ObservedProcess>)>,
    udp: BTreeMap<String, (ObservedUdpEndpoint, Option<ObservedProcess>)>,
}

fn process_key(p: &ObservedProcess) -> String {
    format!("{}:{:?}:{}", p.pid, p.creation_filetime, p.name)
}
fn connection_key(c: &ObservedConnection) -> String {
    format!(
        "{}:{:?}:{}:{}:{}:{}:{}",
        c.pid,
        c.process_creation_filetime,
        c.family,
        c.local_address,
        c.local_port,
        c.remote_address,
        c.remote_port
    )
}

fn observed_parent(
    snapshot: &ObservationSnapshot,
    child: &ObservedProcess,
) -> Option<ObservedProcess> {
    let child_time = child.creation_filetime?;
    // Strictly before the snapshot (including the millisecond uncertainty): the
    // ToolHelp PPID must not be attached to a PID replacement queried afterward.
    if !snapshot.process_complete
        || child.pid == child.parent_pid
        || child.parent_pid == 0
        || child.access_error.is_some()
        || piko_win_platform::observations::filetime_unix_ms(child_time)?
            >= snapshot.started_at_unix_ms
    {
        return None;
    }
    let mut candidates = snapshot
        .processes
        .iter()
        .filter(|p| p.pid == child.parent_pid);
    let parent = candidates.next()?;
    if candidates.next().is_some()
        || parent.access_error.is_some()
        || parent.creation_filetime? >= child_time
        || piko_win_platform::observations::filetime_unix_ms(parent.creation_filetime?)?
            .is_negative()
    {
        return None;
    }
    Some(parent.clone())
}

impl History {
    fn update(&mut self, snapshot: &ObservationSnapshot) -> Vec<Observation> {
        let mut output = Vec::new();
        let at = snapshot.completed_at_unix_ms;
        let processes: BTreeMap<_, _> = snapshot
            .processes
            .iter()
            .map(|p| (process_key(p), p.clone()))
            .collect();
        let mut parents = BTreeMap::new();
        for (key, p) in &processes {
            let old = self.processes.get(key);
            let parent = observed_parent(snapshot, p);
            if old != Some(p) || self.parents.get(key) != parent.as_ref() {
                output.push(Observation {
                    udp: None,
                    transition: if old.is_some() { "changed" } else { "observed" },
                    at,
                    process: Some(p.clone()),
                    parent: parent.clone(),
                    connection: None,
                });
            }
            if let Some(parent) = parent {
                parents.insert(key.clone(), parent);
            }
        }
        if snapshot.process_complete {
            for (key, p) in &self.processes {
                if !processes.contains_key(key) {
                    output.push(Observation {
                        udp: None,
                        transition: "not_observed",
                        at,
                        process: Some(p.clone()),
                        parent: None,
                        connection: None,
                    });
                }
            }
        }
        // Replace bounded baseline even on partial snapshots. Missing rows may be observed
        // anew next time; no absent process is ever inferred from a partial snapshot.
        self.processes = processes;
        self.parents = parents;
        let by_pid: BTreeMap<_, _> = snapshot.processes.iter().map(|p| (p.pid, p)).collect();
        let mut connections = BTreeMap::new();
        for c in &snapshot.connections {
            let process = by_pid
                .get(&c.pid)
                .filter(|p| {
                    c.process_creation_filetime.is_some()
                        && p.creation_filetime == c.process_creation_filetime
                })
                .map(|p| (*p).clone());
            let key = connection_key(c);
            let old = self.connections.get(&key);
            if old.is_none_or(|(previous, _)| previous != c) {
                output.push(Observation {
                    udp: None,
                    transition: if old.is_some() { "changed" } else { "observed" },
                    at,
                    process: process.clone(),
                    parent: None,
                    connection: Some(c.clone()),
                });
            }
            connections.insert(key, (c.clone(), process));
        }
        if snapshot.network_complete {
            for (key, (c, p)) in &self.connections {
                if !connections.contains_key(key) {
                    output.push(Observation {
                        udp: None,
                        transition: "not_observed",
                        at,
                        process: p.clone(),
                        parent: None,
                        connection: Some(c.clone()),
                    });
                }
            }
        }
        self.connections = connections;
        let mut udp = BTreeMap::new();
        for endpoint in &snapshot.udp_endpoints {
            let process = by_pid
                .get(&endpoint.pid)
                .filter(|p| {
                    endpoint.process_creation_filetime.is_some()
                        && p.creation_filetime == endpoint.process_creation_filetime
                })
                .map(|p| (*p).clone());
            let key = format!(
                "{}:{:?}:{}:{}:{}",
                endpoint.pid,
                endpoint.process_creation_filetime,
                endpoint.family,
                endpoint.local_address,
                endpoint.local_port
            );
            let old = self.udp.get(&key);
            if old.is_none_or(|(e, p)| e != endpoint || p != &process) {
                output.push(Observation {
                    transition: if old.is_some() { "changed" } else { "observed" },
                    at,
                    process: process.clone(),
                    parent: None,
                    connection: None,
                    udp: Some(endpoint.clone()),
                });
            }
            udp.insert(key, (endpoint.clone(), process));
        }
        if snapshot.udp_complete == Some(true) {
            for (key, (endpoint, process)) in &self.udp {
                if !udp.contains_key(key) {
                    output.push(Observation {
                        transition: "not_observed",
                        at,
                        process: process.clone(),
                        parent: None,
                        connection: None,
                        udp: Some(endpoint.clone()),
                    });
                }
            }
        }
        self.udp = udp;
        output
    }
}

/// Deterministic UUIDv8; the domain, host, full FILETIME and PID are all bound.
pub fn process_instance(host: Uuid, p: &ObservedProcess) -> Option<Uuid> {
    let time = p.creation_filetime?;
    let mut hash = Sha256::new();
    hash.update(b"piko.process.instance.v1\0");
    hash.update(host.as_bytes());
    hash.update(p.pid.to_le_bytes());
    hash.update(time.to_le_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 15) | 0x80;
    bytes[8] = (bytes[8] & 63) | 0x80;
    Some(Uuid::from_bytes(bytes))
}

pub fn normalize_observation(
    observation: Observation,
    mut event: SecurityEvent,
) -> io::Result<EventRecord> {
    let network = observation.connection.is_some() || observation.udp.is_some();
    event.sensor_id = "windows.observations".into();
    event.event_category = if network { "network" } else { "process" }.into();
    event.event_type = format!(
        "{}.snapshot.{}",
        if observation.udp.is_some() {
            "network.udp"
        } else {
            &event.event_category
        },
        observation.transition
    );
    event.operation = if observation.udp.is_some() {
        "local_bind_snapshot"
    } else {
        "snapshot"
    }
    .into();
    event.result = observation.transition.into();
    event.severity = Severity::Info;
    event.observation_time = observation.at;
    event.wall_clock_time = observation.at;
    event.actor_identity = observation
        .process
        .as_ref()
        .and_then(|p| p.sid.as_ref())
        .map(|sid| IdentityContext {
            sid: Some(sid.clone()),
            display_name: None,
        });
    event.process = observation.process.as_ref().map(|p| ProcessContext {
        pid: p.pid,
        instance_id: process_instance(event.host_id, p),
        name: Some(p.name.clone()),
        executable_path: p.executable.clone(),
        creation_time_unix_ms: p
            .creation_filetime
            .and_then(piko_win_platform::observations::filetime_unix_ms),
    });
    event.parent_process = observation
        .process
        .as_ref()
        .filter(|p| p.parent_pid != 0)
        .map(|p| ProcessContext {
            pid: p.parent_pid,
            instance_id: None,
            name: None,
            executable_path: None,
            creation_time_unix_ms: None,
        });
    if let Some(parent) = observation.parent.as_ref().filter(|parent| {
        observation.process.as_ref().is_some_and(|child| {
            child.parent_pid == parent.pid
                && child.pid != parent.pid
                && matches!((parent.creation_filetime, child.creation_filetime), (Some(p), Some(c)) if p < c)
        })
    }) {
        event.parent_process = Some(ProcessContext {
            pid: parent.pid,
            instance_id: process_instance(event.host_id, parent),
            name: Some(parent.name.clone()),
            executable_path: parent.executable.clone(),
            creation_time_unix_ms: parent.creation_filetime.and_then(piko_win_platform::observations::filetime_unix_ms),
        });
    }
    event.logon_session = None;
    event.causal_parents.clear();
    event.correlation_ids.clear();
    event.integrity_metadata.source_integrity = None;
    event.target = observation.connection.as_ref().map(|c| EventTarget {
        kind: "tcp_endpoint".into(),
        identifier: format!(
            "[{}]:{} -> [{}]:{} (state {})",
            c.local_address, c.local_port, c.remote_address, c.remote_port, c.state
        ),
    });
    if let Some(endpoint) = &observation.udp {
        event.target = Some(EventTarget {
            kind: "udp_local_endpoint".into(),
            identifier: format!("[{}]:{}", endpoint.local_address, endpoint.local_port),
        });
    }
    let evidence_id = Uuid::new_v4();
    event.raw_evidence_reference = Some(evidence_id);
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "piko.observation.v1", "transition": observation.transition, "observed_at": observation.at,
        "process": observation.process, "parent_lifetime": observation.parent, "connection": observation.connection, "udp_local_endpoint": observation.udp,
        "semantics": "polling snapshot; absence is not a proven exit; parent lifetime is resolved only within the same snapshot with strictly earlier creation; PPID is Windows-reported parentage, not proven initiating actor or causality"
    })).map_err(io::Error::other)?;
    event.validate().map_err(io::Error::other)?;
    Ok(EventRecord {
        event,
        raw_evidence: Some(RawEvidence {
            evidence_id,
            source: "windows.observations".into(),
            content_type: "application/json".into(),
            observed_at_unix_ms: observation.at,
            bytes,
        }),
    })
}

impl ObservationCollector {
    pub fn start(host_id: Uuid) -> io::Result<Self> {
        let (sender, records) = mpsc::channel(8);
        let (latest_sender, latest) = watch::channel(None);
        let (health_sender, health) = watch::channel(SensorHealth {
            id: "windows.observations".into(),
            state: "starting".into(),
            detail: "Opening process and TCP snapshot collector".into(),
            last_seen_unix_ms: None,
        });
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        std::thread::Builder::new().name("piko-observations".into()).spawn(move || {
            let mut history = History::default();
            while !stop.load(Ordering::Acquire) && !sender.is_closed() {
                match piko_win_platform::observations::observe() {
                    Ok(mut snapshot) => {
                        for process in &mut snapshot.processes { process.instance_id = process_instance(host_id, process).map(|id| id.to_string()); }
                        let unreadable = snapshot.processes.iter().filter(|p| p.access_error.is_some()).count();
                        health_sender.send_replace(SensorHealth {
                            id: "windows.observations".into(),
                            state: if snapshot.process_complete && snapshot.network_complete && snapshot.udp_complete==Some(true) { "limited" } else { "degraded" }.into(),
                            detail: format!("10s process/TCP/UDP snapshots; short-lived activity may be missed; {} processes, {} TCP rows, {} local UDP binds; {} partially inaccessible processes. {}", snapshot.processes.len(), snapshot.connections.len(), snapshot.udp_endpoints.len(), unreadable, snapshot.warnings.join("; ")),
                            last_seen_unix_ms: Some(snapshot.completed_at_unix_ms),
                        });
                        let records = history.update(&snapshot); latest_sender.send_replace(Some(snapshot));
                        for mut record in records {
                            loop {
                                if stop.load(Ordering::Acquire) { return; }
                                match sender.try_send(record) {
                                    Ok(()) => break,
                                    Err(mpsc::error::TrySendError::Full(value)) => { record = value; std::thread::sleep(Duration::from_millis(25)); },
                                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                                }
                            }
                        }
                    }
                    Err(error) => {
                        latest_sender.send_replace(None);
                        health_sender.send_replace(SensorHealth { id: "windows.observations".into(), state: "degraded".into(), detail: format!("Snapshot failed: {error}; retry in 10s"), last_seen_unix_ms: None });
                    }
                }
                for _ in 0..40 { if stop.load(Ordering::Acquire) || sender.is_closed() { return; } std::thread::sleep(Duration::from_millis(250)); }
            }
        })?;
        Ok(Self {
            records,
            latest,
            health,
            stopped,
        })
    }
    pub fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.records.close();
    }
}
impl Drop for ObservationCollector {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn process(ticks: u64) -> ObservedProcess {
        ObservedProcess {
            instance_id: None,
            pid: 42,
            parent_pid: 7,
            name: "example.exe".into(),
            executable: Some("C:\\example.exe".into()),
            creation_filetime: Some(ticks),
            sid: Some("S-1-5-21-42".into()),
            session_id: Some(2),
            access_error: None,
        }
    }
    fn snapshot() -> ObservationSnapshot {
        ObservationSnapshot {
            started_at_unix_ms: 1,
            completed_at_unix_ms: 2,
            processes: vec![process(133_000_000_000_000_001)],
            connections: vec![],
            udp_endpoints: vec![],
            udp_complete: Some(true),
            process_complete: true,
            network_complete: true,
            warnings: vec![],
        }
    }
    #[test]
    fn identity_preserves_submillisecond_pid_reuse_and_unknowns(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let host = Uuid::new_v4();
        let mut p = process(133_000_000_000_000_001);
        let first = process_instance(host, &p);
        p.creation_filetime = p.creation_filetime.map(|v| v + 1);
        assert_ne!(first, process_instance(host, &p));
        assert_ne!(first, process_instance(Uuid::new_v4(), &p));
        p.creation_filetime = None;
        assert_eq!(process_instance(host, &p), None);
        let json = serde_json::to_string(&snapshot())?;
        assert!(json.contains("\"133000000000000001\""));
        assert_eq!(
            serde_json::from_str::<ObservationSnapshot>(&json)?.processes[0].creation_filetime,
            Some(133_000_000_000_000_001)
        );
        Ok(())
    }
    #[test]
    fn partial_snapshots_never_infer_exit_and_repeated_snapshots_are_quiet() {
        let mut history = History::default();
        let mut s = snapshot();
        assert_eq!(history.update(&s).len(), 1);
        assert!(history.update(&s).is_empty());
        s.processes.clear();
        s.process_complete = false;
        assert!(history.update(&s).is_empty());
        s = snapshot();
        assert_eq!(history.update(&s)[0].transition, "observed");
        s.processes.clear();
        assert_eq!(history.update(&s)[0].transition, "not_observed");
    }
    #[test]
    fn parent_lifetime_is_same_snapshot_and_reuse_or_unknown_stays_unresolved() -> io::Result<()> {
        let mut s = snapshot();
        s.started_at_unix_ms = 1_700_000_000_000;
        s.completed_at_unix_ms = s.started_at_unix_ms + 1;
        let mut parent = process(132_000_000_000_000_001);
        parent.pid = 7;
        parent.parent_pid = 0;
        parent.name = "launcher.exe".into();
        parent.executable = Some("C:\\Example\\launcher.exe".into());
        s.processes.push(parent.clone());
        let host = Uuid::new_v4();
        let mut history = History::default();
        let observations = history.update(&s);
        let child = observations
            .into_iter()
            .find(|o| o.process.as_ref().is_some_and(|p| p.pid == 42))
            .ok_or_else(|| io::Error::other("missing child observation"))?;
        let record = normalize_observation(
            child,
            SecurityEvent::heartbeat(host, Uuid::new_v4(), 1, s.completed_at_unix_ms, 1),
        )?;
        assert_eq!(
            record
                .event
                .parent_process
                .as_ref()
                .and_then(|p| p.instance_id),
            process_instance(host, &parent)
        );
        assert!(record.event.causal_parents.is_empty());
        assert!(String::from_utf8(
            record
                .raw_evidence
                .ok_or_else(|| io::Error::other("missing evidence"))?
                .bytes
        )
        .map_err(io::Error::other)?
        .contains("parent_lifetime"));
        assert!(history.update(&s).is_empty());

        s.process_complete = false;
        assert!(observed_parent(&s, &s.processes[0]).is_none());
        s.process_complete = true;

        // Same PID, newer lifetime: historical child PPID cannot name this process.
        s.processes[1].creation_filetime = Some(134_000_000_000_000_001);
        let changed = history.update(&s);
        let child = changed
            .into_iter()
            .find(|o| o.process.as_ref().is_some_and(|p| p.pid == 42))
            .ok_or_else(|| io::Error::other("missing changed child"))?;
        assert_eq!(child.transition, "changed");
        let record = normalize_observation(
            child,
            SecurityEvent::heartbeat(host, Uuid::new_v4(), 2, s.completed_at_unix_ms, 2),
        )?;
        let unresolved = record
            .event
            .parent_process
            .ok_or_else(|| io::Error::other("missing unresolved parent"))?;
        assert_eq!(unresolved.pid, 7);
        assert!(unresolved.instance_id.is_none() && unresolved.name.is_none());
        s.processes[1] = parent.clone();
        s.processes[1].creation_filetime = None;
        assert!(observed_parent(&s, &s.processes[0]).is_none());
        s.processes[1] = parent.clone();
        s.processes[1].access_error = Some("unavailable".into());
        assert!(observed_parent(&s, &s.processes[0]).is_none());
        s.processes[1] = parent.clone();
        s.processes.push(parent);
        assert!(observed_parent(&s, &s.processes[0]).is_none());
        s.processes.pop();
        s.started_at_unix_ms = piko_win_platform::observations::filetime_unix_ms(
            s.processes[0]
                .creation_filetime
                .ok_or_else(|| io::Error::other("missing creation time"))?,
        )
        .ok_or_else(|| io::Error::other("invalid creation time"))?;
        assert!(observed_parent(&s, &s.processes[0]).is_none());
        Ok(())
    }
    #[test]
    fn ambiguous_connection_does_not_borrow_pid_identity_or_runtime_actor() -> io::Result<()> {
        let mut s = snapshot();
        s.connections.push(ObservedConnection {
            pid: 42,
            process_creation_filetime: None,
            family: "ipv4".into(),
            local_address: "127.0.0.1".into(),
            local_port: 1234,
            remote_address: "127.0.0.1".into(),
            remote_port: 80,
            state: 5,
        });
        let mut history = History::default();
        let changes = history.update(&s);
        let connection = changes
            .into_iter()
            .find(|e| e.connection.is_some())
            .ok_or_else(|| io::Error::other("missing connection"))?;
        let event = normalize_observation(
            connection,
            SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 3, 4),
        )?;
        assert!(event.event.process.is_none());
        assert!(event.event.actor_identity.is_none());
        assert!(event.event.parent_process.is_none());
        assert!(event.event.causal_parents.is_empty());
        assert_eq!(event.event.severity, Severity::Info);
        assert_eq!(event.event.ingestion_time, 3);
        assert_eq!(event.event.observation_time, 2);
        Ok(())
    }
    #[test]
    fn udp_absence_is_not_traffic_and_partial_scans_do_not_infer_removal() -> io::Result<()> {
        let mut s = snapshot();
        s.udp_endpoints.push(ObservedUdpEndpoint {
            pid: 42,
            process_creation_filetime: s.processes[0].creation_filetime,
            family: "ipv4".into(),
            local_address: "127.0.0.1".into(),
            local_port: 5353,
        });
        let mut history = History::default();
        let observations = history.update(&s);
        let observation = observations
            .into_iter()
            .find(|o| o.udp.is_some())
            .ok_or_else(|| io::Error::other("No UDP observation"))?;
        let record = normalize_observation(
            observation,
            SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 1, 1),
        )?;
        assert_eq!(record.event.event_type, "network.udp.snapshot.observed");
        assert_eq!(record.event.operation, "local_bind_snapshot");
        assert_eq!(
            record.event.target.as_ref().map(|t| t.kind.as_str()),
            Some("udp_local_endpoint")
        );
        assert!(history.update(&s).is_empty());
        s.udp_endpoints.clear();
        s.udp_complete = Some(false);
        assert!(history.update(&s).is_empty());
        s.udp_complete = Some(true);
        assert!(history.update(&s).is_empty());
        Ok(())
    }
}
