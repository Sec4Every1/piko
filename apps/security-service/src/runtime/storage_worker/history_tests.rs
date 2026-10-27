use super::{investigation_expression, investigation_page, investigation_query};
use piko_event_schema::{EventTarget, ProcessContext, SecurityEvent};
use piko_event_storage::{SqliteEventStore, StorageConfig, StorageError};
use piko_ipc::ApiData;
use piko_security_core::Investigation;
use std::{error::Error, fs, path::PathBuf};
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("piko-history-worker-{}", Uuid::new_v4()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn open(&self) -> Result<SqliteEventStore, StorageError> {
        SqliteEventStore::open(
            self.0.join("events.sqlite3"),
            StorageConfig {
                retention_months: None,
                ..Default::default()
            },
        )
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn event(store: &SqliteEventStore, instance: Uuid, number: u64, at: i64) -> SecurityEvent {
    let mut event =
        SecurityEvent::heartbeat(store.host_id(), Uuid::from_u128(1), number, 1000, number);
    event.event_id = Uuid::from_u128(1000 + u128::from(number));
    event.sensor_id = "windows.observations".into();
    event.event_type = "process.snapshot.observed".into();
    event.observation_time = at;
    event.process = Some(ProcessContext {
        pid: 20,
        instance_id: Some(instance),
        name: Some("worker.exe".into()),
        executable_path: None,
        creation_time_unix_ms: Some(20),
    });
    event
}

fn graph(answer: ApiData) -> Investigation {
    let ApiData::Investigation(graph) = answer else {
        panic!("expected investigation response")
    };
    graph
}

#[test]
fn invalid_windows_and_cursors_are_rejected_before_querying() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let store = directory.open()?;
    let instance = Uuid::from_u128(10);
    for window in [
        (-1, 100),
        (100, 100),
        (101, 100),
        (0, 8_640_000_000_000_001),
    ] {
        assert!(matches!(
            investigation_expression(instance, Some(window)),
            Err(StorageError::InvalidQuery)
        ));
        assert!(matches!(
            investigation_query(&store, instance, Some(window)),
            Err(StorageError::InvalidQuery)
        ));
        assert!(matches!(
            investigation_page(&store, instance, Some(window), None),
            Err(StorageError::InvalidQuery)
        ));
    }
    for (window, time) in [
        (None, -1),
        (None, 8_640_000_000_000_001),
        (Some((100, 200)), 99),
        (Some((100, 200)), 200),
    ] {
        assert!(matches!(
            investigation_page(&store, instance, window, Some((time, Uuid::from_u128(100)))),
            Err(StorageError::InvalidQuery)
        ));
    }
    assert!(investigation_page(
        &store,
        instance,
        Some((100, 200)),
        Some((100, Uuid::from_u128(100)))
    )
    .is_ok());
    Ok(())
}

#[test]
fn page_cursor_uses_last_query_row_even_when_display_sorts_ascending() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let instance = Uuid::from_u128(10);
    let events: Vec<_> = (1..=130)
        .map(|number| event(&store, instance, number, 100))
        .collect();
    for batch in events.chunks(128) {
        store.append_batch(batch)?;
    }
    let first = graph(investigation_page(&store, instance, None, None)?);
    assert!(first.observation_paging_available);
    assert!(first.query_truncated);
    assert_eq!(first.events_considered, 128);
    assert_eq!(first.observations.len(), 128);
    // Query order is 130..3, while display order is 3..130.
    assert_eq!(
        first.next_observation_cursor,
        Some((100, events[2].event_id))
    );
    assert_eq!(first.observations[0].event_id, events[2].event_id);
    assert_eq!(first.observations[127].event_id, events[129].event_id);
    let second = graph(investigation_page(
        &store,
        instance,
        None,
        first.next_observation_cursor,
    )?);
    assert_eq!(second.observations.len(), 2);
    assert!(!second.query_truncated);
    assert!(second.next_observation_cursor.is_none());
    assert_eq!(
        second
            .observations
            .iter()
            .map(|row| row.event_id)
            .collect::<Vec<_>>(),
        vec![events[0].event_id, events[1].event_id]
    );
    let mut ids: Vec<_> = first
        .observations
        .iter()
        .chain(&second.observations)
        .map(|row| row.event_id)
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        events
            .iter()
            .map(|event| event.event_id)
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn window_admits_child_with_own_attribution_and_excludes_upper_boundary(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let parent = Uuid::from_u128(10);
    let child = Uuid::from_u128(11);
    let mut included = event(&store, child, 1, 100);
    included.parent_process = Some(ProcessContext {
        pid: 10,
        instance_id: Some(parent),
        name: Some("launcher.exe".into()),
        executable_path: None,
        creation_time_unix_ms: Some(10),
    });
    let mut upper = included.clone();
    upper.event_id = Uuid::from_u128(1002);
    upper.sequence = 2;
    upper.observation_time = 200;
    let mut lower = included.clone();
    lower.event_id = Uuid::from_u128(1003);
    lower.sequence = 3;
    lower.observation_time = 99;
    store.append_batch(&[included.clone(), upper, lower])?;
    for result in [
        investigation_query(&store, parent, Some((100, 200)))?,
        investigation_page(&store, parent, Some((100, 200)), None)?,
    ] {
        let result = graph(result);
        assert_eq!(result.events_considered, 1);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].event_id, included.event_id);
        assert_eq!(result.observations[0].process_instance, child);
        assert_eq!(result.observations[0].process_name, "worker.exe");
        let root = result
            .nodes
            .iter()
            .find(|node| node.id == "process")
            .ok_or("missing root process node")?;
        assert_eq!(root.label, "launcher.exe");
        assert_eq!(root.instance_id, Some(parent));
    }
    Ok(())
}

#[test]
fn unwindowed_query_includes_udp_bind_without_remote_inference() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let instance = Uuid::from_u128(10);
    let mut observed = event(&store, instance, 1, 100);
    observed.event_type = "network.udp.snapshot.observed".into();
    observed.target = Some(EventTarget {
        kind: "udp_local_endpoint".into(),
        identifier: "[0.0.0.0]:5353".into(),
    });
    store.append_batch(&[observed])?;
    let result = graph(investigation_query(&store, instance, None)?);
    assert_eq!(result.observations.len(), 1);
    assert!(!result.observation_paging_available);
    assert_eq!(result.edges.len(), 1);
    assert_eq!(result.edges[0].relation, "observed_udp_bind");
    Ok(())
}
