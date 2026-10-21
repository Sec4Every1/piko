//! Evidence-backed associations only: no attack verdict or initiating-actor inference.
use piko_event_schema::SecurityEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

const MAX_NODES: usize = 64;
const MAX_REFERENCES: usize = 16;
pub const MAX_INVESTIGATION_EVENTS: usize = 500;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationNode {
    pub id: String,
    pub kind: String,
    pub label: String,
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
    };
    let mut nodes = BTreeMap::<(String, String), String>::new();
    let mut edges = BTreeMap::<(String, String), usize>::new();
    let mut seen = HashSet::new();
    for event in events.iter().take(MAX_INVESTIGATION_EVENTS) {
        if event.process.as_ref().and_then(|p| p.instance_id) != Some(instance)
            || event.sensor_id != "windows.observations"
            || !seen.insert(event.event_id)
            || !matches!(
                event.event_type.as_str(),
                "process.snapshot.observed"
                    | "process.snapshot.changed"
                    | "network.snapshot.observed"
                    | "network.snapshot.changed"
            )
        {
            continue;
        }
        graph.events_considered += 1;
        if graph.nodes.is_empty() {
            let mut label = event
                .process
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
            });
        }
        let mut associations = Vec::new();
        if let Some(sid) = event
            .actor_identity
            .as_ref()
            .and_then(|id| id.sid.as_deref())
        {
            associations.push(("identity", sid.to_string(), sid, "observed_identity"));
        }
        if event.event_type.starts_with("process.snapshot.") {
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
                            ));
                        }
                    }
                }
            }
        }
        if event.event_type.starts_with("network.") {
            if let Some(target) = &event.target {
                if target.kind == "tcp_endpoint" {
                    associations.push((
                        "tcp_endpoint",
                        target.identifier.clone(),
                        target.identifier.as_str(),
                        "observed_tcp",
                    ));
                }
            }
        }
        for (kind, identity, label, relation) in associations {
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
