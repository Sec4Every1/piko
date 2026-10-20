//! Reduce repeated file-context observations, never classify code as harmless.
use super::image_files::{self, FileFingerprint, HeldImage};
use piko_event_schema::{EventRecord, RawEvidence};
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;
const MAX_CONTEXTS: usize = 1024;
#[derive(Clone)]
struct Actor {
    instance: Uuid,
    birth: i64,
    path: String,
    session: u32,
    exit: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Context {
    pub application: FileFingerprint,
    pub module: FileFingerprint,
    pub session: u32,
    pub signature: String,
}
#[derive(Clone)]
struct Anchor {
    event: Uuid,
    evidence: Uuid,
    at: Instant,
}
pub struct Prepared {
    pub records: Vec<EventRecord>,
    anchors: Vec<(Context, Anchor)>,
    pub summarized: u64,
}
#[derive(Default)]
pub struct Repetition {
    actors: HashMap<u32, Actor>,
    anchors: HashMap<Context, Anchor>,
    pub summarized: u64,
    pub inspected: u64,
    pub passthrough: u64,
}
struct Group {
    last: EventRecord,
    context: Context,
    anchor: Anchor,
    count: u64,
    first: i64,
    last_time: i64,
}
impl Repetition {
    pub fn commit(&mut self, prepared: &Prepared) {
        for (key, anchor) in &prepared.anchors {
            if self.anchors.len() < MAX_CONTEXTS {
                self.anchors.insert(key.clone(), anchor.clone());
            }
        }
        self.summarized = self.summarized.saturating_add(prepared.summarized);
    }
    pub fn prepare(&mut self, batch: Vec<EventRecord>, coverage: bool) -> Prepared {
        self.anchors
            .retain(|_, a| a.at.elapsed() < Duration::from_secs(300));
        if !coverage {
            self.anchors.clear();
            self.actors.clear();
            self.passthrough = self.passthrough.saturating_add(
                batch
                    .iter()
                    .filter(|record| record.event.event_type == "image.etw.loaded")
                    .count() as u64,
            );
            return Prepared {
                records: batch,
                anchors: Vec::new(),
                summarized: 0,
            };
        }
        // Pre-read completed lifetimes in this same batch, including fast processes.
        // Both start and stop must identify the same FILETIME-derived instance.
        for record in &batch {
            let e = &record.event;
            if e.sensor_id != "windows.etw.process_image" || e.result != "observed" {
                continue;
            }
            let Some(p) = &e.process else {
                continue;
            };
            if e.event_type == "process.etw.started" {
                if let (Some(instance), Some(birth), Some(path), Some(raw)) = (
                    p.instance_id,
                    p.creation_time_unix_ms,
                    p.executable_path.as_ref(),
                    record.raw_evidence.as_ref(),
                ) {
                    let session = serde_json::from_slice::<serde_json::Value>(&raw.bytes)
                        .ok()
                        .and_then(|v| v["tdh_fields"]["session_id"].as_u64())
                        .and_then(|v| u32::try_from(v).ok());
                    if self.actors.len() < 4096 {
                        if let Some(session) = session {
                            self.actors.insert(
                                p.pid,
                                Actor {
                                    instance,
                                    birth,
                                    path: path.clone(),
                                    session,
                                    exit: None,
                                },
                            );
                        }
                    }
                }
            } else if e.event_type == "process.etw.stopped" {
                if let Some(actor) = self.actors.get_mut(&p.pid) {
                    if p.instance_id == Some(actor.instance) {
                        actor.exit = Some(e.wall_clock_time);
                    } else {
                        self.actors.remove(&p.pid);
                    }
                }
            }
        }
        let deadline = Instant::now() + Duration::from_millis(150);
        let mut files: HashMap<String, HeldImage> = HashMap::new();
        let mut signatures: HashMap<String, Option<String>> = HashMap::new();
        let mut new_anchors: HashMap<Context, Anchor> = HashMap::new();
        let mut groups: HashMap<Context, Group> = HashMap::new();
        let mut output = Vec::new();
        for mut record in batch {
            let proof = (|| -> Option<Context> {
                let e = &record.event;
                if e.sensor_id != "windows.etw.process_image"
                    || e.event_type != "image.etw.loaded"
                    || e.result != "observed"
                    || e.severity != piko_event_schema::Severity::Info
                    || Instant::now() >= deadline
                {
                    return None;
                }
                let p = e.process.as_ref()?;
                let actor = self.actors.get(&p.pid)?;
                let target = e.target.as_ref()?;
                if target.kind != "loaded_image"
                    || e.wall_clock_time < actor.birth
                    || e.observation_time.abs_diff(e.wall_clock_time) > 5000
                    || actor.exit.is_some_and(|exit| e.wall_clock_time > exit)
                {
                    return None;
                }
                if actor.exit.is_none() {
                    let current = piko_win_platform::observations::inspect_process(p.pid);
                    if current
                        .creation_filetime
                        .and_then(piko_win_platform::observations::filetime_unix_ms)
                        != Some(actor.birth)
                    {
                        return None;
                    }
                }
                for path in [&actor.path, &target.identifier] {
                    if !files.contains_key(path) {
                        if files.len() >= 64 {
                            return None;
                        }
                        files.insert(path.clone(), image_files::inspect(path, deadline).ok()?);
                    }
                }
                let application = files.get(&actor.path)?.fingerprint.clone();
                let module = files.get(&target.identifier)?;
                let signature = if let Some(value) = signatures.get(&target.identifier) {
                    value.clone()
                } else {
                    let value = piko_win_platform::signature::verify_local(
                        &module.file,
                        &module.fingerprint.path,
                    )
                    .ok()
                    .flatten()
                    .map(str::to_owned);
                    signatures.insert(target.identifier.clone(), value.clone());
                    value
                }?;
                Some(Context {
                    application,
                    module: module.fingerprint.clone(),
                    session: actor.session,
                    signature,
                })
            })();
            let Some(context) = proof else {
                if record.event.event_type == "image.etw.loaded" {
                    self.passthrough = self.passthrough.saturating_add(1);
                }
                output.push(record);
                continue;
            };
            self.inspected = self.inspected.saturating_add(1);
            let Some(raw) = record.raw_evidence.as_mut() else {
                self.passthrough = self.passthrough.saturating_add(1);
                output.push(record);
                continue;
            };
            let anchor = self
                .anchors
                .get(&context)
                .or_else(|| new_anchors.get(&context))
                .cloned();
            if let Some(anchor) = anchor {
                let time = record.event.wall_clock_time;
                let group = groups.entry(context.clone()).or_insert_with(|| Group {
                    last: record.clone(),
                    context: context.clone(),
                    anchor,
                    count: 0,
                    first: time,
                    last_time: time,
                });
                group.count += 1;
                group.first = group.first.min(time);
                group.last_time = group.last_time.max(time);
                group.last = record;
            } else {
                // A new/changed pairing always retains the full native payload plus file
                // snapshots. The source event and the inspected disk file are distinct facts.
                if self.anchors.len() + new_anchors.len() >= MAX_CONTEXTS {
                    self.passthrough = self.passthrough.saturating_add(1);
                    output.push(record);
                    continue;
                }
                if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&raw.bytes) {
                    value["file_context_snapshot"] =
                        serde_json::to_value(&context).unwrap_or(serde_json::Value::Null);
                    if let Ok(bytes) = serde_json::to_vec(&value) {
                        raw.bytes = bytes;
                    }
                }
                new_anchors.insert(
                    context,
                    Anchor {
                        event: record.event.event_id,
                        evidence: raw.evidence_id,
                        at: Instant::now(),
                    },
                );
                output.push(record);
            }
        }
        let mut summarized = 0;
        for (_, group) in groups {
            let mut record = group.last;
            let evidence_id = Uuid::new_v4();
            let bytes = serde_json::to_vec(
                &serde_json::json!({"schema":"piko.image.repetition.v1","context":group.context,"count":group.count,"first_event_time":group.first,"last_event_time":group.last_time,"sample_event_id":group.anchor.event,"sample_evidence_id":group.anchor.evidence,"semantics":"Derived summary of repeated file-context observations, not native ETW raw or a benign verdict; token/parent/memory integrity not established; signature local, no online revocation."}),
            );
            let Ok(bytes) = bytes else {
                continue;
            };
            record.event.event_id = Uuid::new_v4();
            record.event.sensor_id = "piko.image_context".into();
            record.event.event_type = "image.etw.repeated".into();
            record.event.operation = "summarize_image_loads".into();
            record.event.result = "aggregated_observations".into();
            record.event.correlation_ids = vec![group.anchor.event];
            record.event.process = None;
            record.event.raw_evidence_reference = Some(evidence_id);
            record.raw_evidence = Some(RawEvidence {
                evidence_id,
                source: "piko.image_context".into(),
                content_type: "application/json".into(),
                observed_at_unix_ms: record.event.observation_time,
                bytes,
            });
            summarized += group.count;
            output.push(record);
        }
        output.sort_by_key(|r| r.event.sequence);
        Prepared {
            records: output,
            anchors: new_anchors.into_iter().collect(),
            summarized,
        }
    }
}
