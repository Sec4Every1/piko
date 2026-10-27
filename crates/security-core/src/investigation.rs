//! Evidence-backed associations only: no attack verdict or initiating-actor inference.
use piko_event_schema::SecurityEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

const MAX_NODES: usize = 64;
const MAX_REFERENCES: usize = 16;
const MAX_OBSERVATIONS: usize = 128;
const MAX_OBSERVATION_LABEL_BYTES: usize = 64 * 1024;
pub const MAX_INVESTIGATION_EVENTS: usize = 500;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub instance_id: Option<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
    pub event_ids: Vec<Uuid>,
    pub evidence_ids: Vec<Uuid>,
    pub observation_count: usize,
    pub first_observed: i64,
    pub last_observed: i64,
}
/// An admitted snapshot's own process and references, ordered for display only.
/// Observation timestamps do not establish causal or process execution order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationObservation {
    pub event_id: Uuid,
    pub evidence_id: Option<Uuid>,
    pub process_instance: Uuid,
    pub event_type: String,
    pub observed_at: i64,
    pub process_name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Investigation {
    pub process_instance: Uuid,
    pub events_considered: usize,
    pub query_truncated: bool,
    pub graph_truncated: bool,
    pub references_truncated: bool,
    pub nodes: Vec<InvestigationNode>,
    pub edges: Vec<InvestigationEdge>,
    #[serde(default)]
    pub observations: Vec<InvestigationObservation>,
    #[serde(default)]
    pub observations_truncated: bool,
    /// Old services omit the timeline; an absent field is not an empty history.
    #[serde(default)]
    pub observations_available: bool,
    #[serde(default)]
    pub observation_paging_available: bool,
    #[serde(default)]
    pub next_observation_cursor: Option<(i64, Uuid)>,
}

pub fn investigate(
    instance: Uuid,
    events: &[SecurityEvent],
    query_truncated: bool,
) -> Investigation {
    let mut graph = Investigation {
        process_instance: instance,
        events_considered: 0,
        query_truncated: query_truncated || events.len() > MAX_INVESTIGATION_EVENTS,
        graph_truncated: false,
        references_truncated: false,
        nodes: Vec::new(),
        edges: Vec::new(),
        observations: Vec::new(),
        observations_truncated: false,
        observations_available: true,
        observation_paging_available: false,
        next_observation_cursor: None,
    };
    let mut nodes = BTreeMap::<(String, String), String>::new();
    let mut edges = BTreeMap::<(String, String), usize>::new();
    let mut seen = HashSet::new();
    let mut observation_label_bytes = 0usize;
    for event in events.iter().take(MAX_INVESTIGATION_EVENTS) {
        if event.sensor_id != "windows.observations"
            || !seen.insert(event.event_id)
            || !matches!(
                event.event_type.as_str(),
                "process.snapshot.observed"
                    | "process.snapshot.changed"
                    | "network.snapshot.observed"
                    | "network.snapshot.changed"
                    | "network.udp.snapshot.observed"
                    | "network.udp.snapshot.changed"
            )
        {
            continue;
        }
        let is_requested_process =
            event.process.as_ref().and_then(|p| p.instance_id) == Some(instance);
        let observed_child = if !is_requested_process
            && event.event_type.starts_with("process.snapshot.")
        {
            match (&event.process, &event.parent_process) {
                (Some(child), Some(parent))
                    if parent.instance_id == Some(instance)
                        && child
                            .instance_id
                            .is_some_and(|id| !id.is_nil() && id != instance)
                        && child.pid != parent.pid
                        && matches!((parent.creation_time_unix_ms, child.creation_time_unix_ms), (Some(p), Some(c)) if p <= c && p >= 0 && c < event.observation_time) =>
                {
                    Some(child)
                }
                _ => None,
            }
        } else {
            None
        };
        if !is_requested_process && observed_child.is_none() {
            continue;
        }
        // Both accepted branches require the event's actual process instance.
        // Never borrow the root/parent label for a child snapshot observation.
        let Some(process) = event.process.as_ref() else {
            continue;
        };
        let Some(process_instance) = process.instance_id else {
            continue;
        };
        graph.events_considered += 1;
        if graph.observations.len() < MAX_OBSERVATIONS {
            let supplied_name = process
                .executable_path
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .or_else(|| {
                    process
                        .name
                        .as_deref()
                        .filter(|name| !name.trim().is_empty())
                });
            let mut process_name = match supplied_name {
                Some(name) if name.len() <= 8192 => name.to_owned(),
                Some(_) => {
                    graph.observations_truncated = true;
                    process_instance.to_string()
                }
                None => process_instance.to_string(),
            };
            // Bound aggregate labels as well as row count: serialized escaping
            // must leave room for the existing graph inside the IPC frame.
            // Reserve a UUID label for every remaining row so paging never
            // advances past an admitted observation solely due to label size.
            if observation_label_bytes
                + process_name.len()
                + (MAX_OBSERVATIONS - graph.observations.len() - 1) * 36
                > MAX_OBSERVATION_LABEL_BYTES
            {
                process_name = process_instance.to_string();
                graph.observations_truncated = true;
            }
            if observation_label_bytes + process_name.len() <= MAX_OBSERVATION_LABEL_BYTES {
                observation_label_bytes += process_name.len();
                graph.observations.push(InvestigationObservation {
                    event_id: event.event_id,
                    evidence_id: event.raw_evidence_reference,
                    process_instance,
                    event_type: event.event_type.clone(),
                    observed_at: event.observation_time,
                    process_name,
                });
            } else {
                graph.observations_truncated = true;
            }
        } else {
            graph.observations_truncated = true;
        }
        if graph.nodes.is_empty() {
            let root_process = if is_requested_process {
                &event.process
            } else {
                &event.parent_process
            };
            let mut label = root_process
                .as_ref()
                .and_then(|p| p.executable_path.clone().or(p.name.clone()))
                .unwrap_or_else(|| instance.to_string());
            if label.len() > 8192 {
                label = instance.to_string();
                graph.graph_truncated = true;
            }
            graph.nodes.push(InvestigationNode {
                id: "process".into(),
                kind: "process".into(),
                label,
                instance_id: Some(instance),
            });
        }
        let mut associations = Vec::new();
        let child_identity = observed_child
            .and_then(|child| child.instance_id)
            .map(|id| id.to_string());
        if let (Some(child), Some(identity)) = (observed_child, child_identity.as_ref()) {
            associations.push((
                "child_process",
                identity.clone(),
                child
                    .executable_path
                    .as_deref()
                    .or(child.name.as_deref())
                    .unwrap_or(identity.as_str()),
                "observed_child",
                child.instance_id,
            ));
        }
        if let Some(sid) = event
            .actor_identity
            .as_ref()
            .filter(|_| is_requested_process)
            .and_then(|id| id.sid.as_deref())
        {
            associations.push((
                "identity",
                sid.to_string(),
                event
                    .actor_identity
                    .as_ref()
                    .and_then(|identity| identity.display_name.as_deref())
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or(sid),
                "observed_identity",
                None,
            ));
        }
        if is_requested_process && event.event_type.starts_with("process.snapshot.") {
            if let (Some(child), Some(parent)) = (&event.process, &event.parent_process) {
                if let Some(parent_instance) = parent
                    .instance_id
                    .filter(|id| !id.is_nil() && *id != instance)
                {
                    if child.pid != parent.pid
                        && matches!((parent.creation_time_unix_ms, child.creation_time_unix_ms), (Some(p), Some(c)) if p <= c && p >= 0 && c < event.observation_time)
                    {
                        if let Some(label) =
                            parent.executable_path.as_deref().or(parent.name.as_deref())
                        {
                            associations.push((
                                "parent_process",
                                parent_instance.to_string(),
                                label,
                                "observed_parent",
                                Some(parent_instance),
                            ));
                        }
                    }
                }
            }
        }
        if is_requested_process && event.event_type.starts_with("network.") {
            if let Some(target) = &event.target {
                if target.kind == "tcp_endpoint" {
                    associations.push((
                        "tcp_endpoint",
                        target.identifier.clone(),
                        target.identifier.as_str(),
                        "observed_tcp",
                        None,
                    ));
                } else if target.kind == "udp_local_endpoint" {
                    associations.push((
                        "udp_local_endpoint",
                        target.identifier.clone(),
                        target.identifier.as_str(),
                        "observed_udp_bind",
                        None,
                    ));
                }
            }
        }
        for (kind, identity, label, relation, instance_id) in associations {
            // Schema permits large user text; graph output has its own display/byte budget.
            if label.len() > 8192 {
                graph.graph_truncated = true;
                continue;
            }
            let key = (kind.to_string(), identity);
            let target = if let Some(id) = nodes.get(&key) {
                id.clone()
            } else {
                if graph.nodes.len() >= MAX_NODES {
                    graph.graph_truncated = true;
                    continue;
                }
                let id = format!("node-{}", graph.nodes.len());
                graph.nodes.push(InvestigationNode {
                    id: id.clone(),
                    kind: kind.into(),
                    label: label.into(),
                    instance_id,
                });
                nodes.insert(key, id.clone());
                id
            };
            let edge_key = (target.clone(), relation.to_string());
            let index = if let Some(index) = edges.get(&edge_key) {
                *index
            } else {
                let index = graph.edges.len();
                graph.edges.push(InvestigationEdge {
                    source: "process".into(),
                    target,
                    relation: relation.into(),
                    event_ids: vec![],
                    evidence_ids: vec![],
                    observation_count: 0,
                    first_observed: event.observation_time,
                    last_observed: event.observation_time,
                });
                edges.insert(edge_key, index);
                index
            };
            let edge = &mut graph.edges[index];
            edge.observation_count += 1;
            edge.first_observed = edge.first_observed.min(event.observation_time);
            edge.last_observed = edge.last_observed.max(event.observation_time);
            if edge.event_ids.len() < MAX_REFERENCES {
                edge.event_ids.push(event.event_id);
                if let Some(id) = event.raw_evidence_reference {
                    edge.evidence_ids.push(id);
                }
            } else {
                graph.references_truncated = true;
            }
        }
    }
    // Retain admitted events in query order while row/label budgets permit,
    // then present observation times ascending. UUIDs break equal-time ties.
    graph
        .observations
        .sort_by_key(|entry| (entry.observed_at, entry.event_id));
    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use piko_event_schema::{EventTarget, IdentityContext};
    fn record(instance: Uuid) -> SecurityEvent {
        let mut e = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 20, 1);
        e.sensor_id = "windows.observations".into();
        e.event_type = "network.snapshot.observed".into();
        if let Some(p) = &mut e.process {
            p.instance_id = Some(instance);
            p.name = Some("example.exe".into());
        }
        e.target = Some(EventTarget {
            kind: "tcp_endpoint".into(),
            identifier: "[127.0.0.1]:123 -> [127.0.0.1]:443 (state 5)".into(),
        });
        e.actor_identity = Some(IdentityContext {
            sid: Some("S-1-5-21-42".into()),
            display_name: None,
        });
        e
    }
    #[test]
    fn graph_uses_event_references_without_inventing_causality_or_pid_links() {
        let id = Uuid::new_v4();
        let e = record(id);
        let graph = investigate(id, &[e.clone(), e.clone()], false);
        assert_eq!(graph.events_considered, 1);
        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.edges.len(), 2);
        assert!(graph
            .edges
            .iter()
            .all(|edge| edge.event_ids == [e.event_id] && edge.observation_count == 1));
        assert!(investigate(Uuid::new_v4(), std::slice::from_ref(&e), false)
            .nodes
            .is_empty());
        let mut gone = e;
        gone.event_type = "network.snapshot.not_observed".into();
        assert!(investigate(id, &[gone], false).nodes.is_empty());
    }
    #[test]
    fn graph_and_reference_bounds_are_explicit() {
        let id = Uuid::new_v4();
        let mut events: Vec<_> = (0..80).map(|_| record(id)).collect();
        let graph = investigate(id, &events, true);
        assert!(graph.query_truncated && graph.references_truncated);
        assert_eq!(graph.edges[0].event_ids.len(), 16);
        for (i, event) in events.iter_mut().enumerate() {
            if let Some(target) = &mut event.target {
                target.identifier = i.to_string();
            }
        }
        let graph = investigate(id, &events, false);
        assert!(graph.graph_truncated);
        assert_eq!(graph.nodes.len(), MAX_NODES);
    }
    #[test]
    fn parent_edges_require_lifetime_and_preserve_distinct_instances_with_same_name() {
        let instance = Uuid::new_v4();
        let mut first = record(instance);
        first.event_type = "process.snapshot.observed".into();
        first.process.as_mut().unwrap().creation_time_unix_ms = Some(10);
        let mut parent = first.process.clone().unwrap();
        parent.pid = 7;
        parent.instance_id = Some(Uuid::new_v4());
        parent.creation_time_unix_ms = Some(5);
        parent.name = Some("launcher.exe".into());
        first.parent_process = Some(parent);
        let mut second = first.clone();
        second.event_id = Uuid::new_v4();
        second.parent_process.as_mut().unwrap().instance_id = Some(Uuid::new_v4());
        let graph = investigate(instance, &[first.clone(), second], false);
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|e| e.relation == "observed_parent")
                .count(),
            2
        );
        assert!(graph.edges.iter().all(|e| !e.event_ids.is_empty()));
        for mutation in 0..4 {
            let mut invalid = first.clone();
            let parent = invalid.parent_process.as_mut().unwrap();
            match mutation {
                0 => parent.instance_id = None,
                1 => parent.instance_id = Some(instance),
                2 => parent.creation_time_unix_ms = Some(11),
                _ => invalid.process.as_mut().unwrap().creation_time_unix_ms = Some(21),
            }
            assert!(!investigate(instance, &[invalid], false)
                .edges
                .iter()
                .any(|e| e.relation == "observed_parent"));
        }
    }
}
