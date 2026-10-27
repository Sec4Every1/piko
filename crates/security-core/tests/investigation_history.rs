use piko_event_schema::{EventTarget, ProcessContext, SecurityEvent};
use piko_security_core::investigate;
use uuid::Uuid;

fn process(instance: Uuid, pid: u32, name: &str, created: i64) -> ProcessContext {
    ProcessContext {
        pid,
        instance_id: Some(instance),
        name: Some(name.into()),
        executable_path: None,
        creation_time_unix_ms: Some(created),
    }
}

fn snapshot(instance: Uuid, event_number: u128, observed_at: i64) -> SecurityEvent {
    let mut event = SecurityEvent::heartbeat(Uuid::from_u128(1), Uuid::from_u128(2), 1, 100, 1);
    event.event_id = Uuid::from_u128(event_number);
    event.sensor_id = "windows.observations".into();
    event.event_type = "process.snapshot.observed".into();
    event.observation_time = observed_at;
    event.process = Some(process(instance, 20, "worker.exe", 20));
    event
}

#[test]
fn child_only_history_keeps_child_attribution_and_parent_root_label() {
    let parent = Uuid::from_u128(10);
    let child = Uuid::from_u128(11);
    let mut event = snapshot(child, 100, 100);
    event.parent_process = Some(process(parent, 10, "launcher.exe", 10));
    event.raw_evidence_reference = Some(Uuid::from_u128(200));

    let graph = investigate(parent, std::slice::from_ref(&event), false);
    assert_eq!(graph.events_considered, 1);
    assert!(graph.observations_available);
    assert_eq!(graph.observations.len(), 1);
    let row = &graph.observations[0];
    assert_eq!(row.process_instance, child);
    assert_eq!(row.process_name, "worker.exe");
    assert_eq!(row.event_id, event.event_id);
    assert_eq!(row.evidence_id, event.raw_evidence_reference);
    assert_eq!(row.observed_at, 100);
    let root = graph
        .nodes
        .iter()
        .find(|node| node.id == "process")
        .unwrap();
    assert_eq!(root.instance_id, Some(parent));
    assert_eq!(root.label, "launcher.exe");
    let child_node = graph
        .nodes
        .iter()
        .find(|node| node.instance_id == Some(child))
        .unwrap();
    assert_eq!(child_node.label, "worker.exe");
    assert!(graph.edges.iter().any(|edge| {
        edge.source == root.id
            && edge.target == child_node.id
            && edge.relation == "observed_child"
            && edge.event_ids == [event.event_id]
    }));
}

#[test]
fn parent_lifetime_must_be_proven_for_both_directions() {
    let parent = Uuid::from_u128(10);
    let child = Uuid::from_u128(11);
    for (parent_time, child_time) in [
        (None, Some(20)),
        (Some(10), None),
        (Some(-1), Some(20)),
        (Some(21), Some(20)),
        (Some(10), Some(100)),
        (Some(10), Some(101)),
    ] {
        let mut event = snapshot(child, 100, 100);
        event.parent_process = Some(process(parent, 10, "launcher.exe", 10));
        event.parent_process.as_mut().unwrap().creation_time_unix_ms = parent_time;
        event.process.as_mut().unwrap().creation_time_unix_ms = child_time;

        let parent_view = investigate(parent, std::slice::from_ref(&event), false);
        assert_eq!(parent_view.events_considered, 0);
        assert!(parent_view.observations.is_empty());
        assert!(parent_view.nodes.is_empty());

        let child_view = investigate(child, &[event], false);
        assert_eq!(child_view.events_considered, 1);
        assert_eq!(child_view.observations[0].process_instance, child);
        assert!(!child_view
            .edges
            .iter()
            .any(|edge| edge.relation == "observed_parent"));
    }
}

#[test]
fn udp_local_bind_is_displayed_without_remote_or_parent_inference() {
    let instance = Uuid::from_u128(10);
    let mut event = snapshot(instance, 100, 100);
    event.event_type = "network.udp.snapshot.observed".into();
    event.target = Some(EventTarget {
        kind: "udp_local_endpoint".into(),
        identifier: "[0.0.0.0]:5353".into(),
    });
    event.parent_process = Some(process(Uuid::from_u128(11), 10, "launcher.exe", 10));
    let graph = investigate(instance, &[event], false);
    assert_eq!(graph.observations.len(), 1);
    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.edges[0].relation, "observed_udp_bind");
    assert_eq!(graph.nodes.len(), 2);
    assert!(graph
        .nodes
        .iter()
        .any(|node| { node.kind == "udp_local_endpoint" && node.label == "[0.0.0.0]:5353" }));
}

#[test]
fn equal_time_rows_have_stable_event_id_order_independent_of_input_order() {
    let instance = Uuid::from_u128(10);
    let events = vec![
        snapshot(instance, 103, 100),
        snapshot(instance, 101, 100),
        snapshot(instance, 104, 90),
        snapshot(instance, 102, 100),
    ];
    let first = investigate(instance, &events, false);
    let reversed: Vec<_> = events.into_iter().rev().collect();
    let second = investigate(instance, &reversed, false);
    let ids = |graph: &piko_security_core::Investigation| {
        graph
            .observations
            .iter()
            .map(|row| row.event_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&first), ids(&second));
    assert_eq!(
        ids(&first),
        [104, 101, 102, 103].map(Uuid::from_u128).to_vec()
    );
    assert!(!first.observations_truncated);
}

#[test]
fn row_cap_reports_omitted_history_without_hiding_considered_events() {
    let instance = Uuid::from_u128(10);
    let events: Vec<_> = (0..129)
        .map(|index| snapshot(instance, 1000 + index, 100))
        .collect();
    let at_limit = investigate(instance, &events[..128], false);
    assert_eq!(at_limit.observations.len(), 128);
    assert!(!at_limit.observations_truncated);
    let over_limit = investigate(instance, &events, false);
    assert_eq!(over_limit.events_considered, 129);
    assert_eq!(over_limit.observations.len(), 128);
    assert!(over_limit.observations_truncated);
    assert!(!over_limit.query_truncated);
    assert!(!over_limit.observation_paging_available);
    assert!(over_limit.next_observation_cursor.is_none());
    assert_eq!(
        over_limit.observations.first().unwrap().event_id,
        events[0].event_id
    );
    assert_eq!(
        over_limit.observations.last().unwrap().event_id,
        events[127].event_id
    );
}
