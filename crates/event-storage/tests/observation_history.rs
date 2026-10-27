use std::{error::Error, fs, path::PathBuf};

use piko_event_schema::{ProcessContext, SecurityEvent};
use piko_event_storage::{EventQuery, SqliteEventStore, StorageConfig, StorageError};
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("piko-observation-test-{}", Uuid::new_v4()));
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

fn observation(store: &SqliteEventStore, number: u64, observed: i64) -> SecurityEvent {
    let mut event = SecurityEvent::heartbeat(
        store.host_id(),
        Uuid::from_u128(10),
        number,
        10_000 + number as i64,
        number,
    );
    event.event_id = Uuid::from_u128(1000 + u128::from(number));
    event.sensor_id = "windows.observations".into();
    event.event_type = "process.snapshot.observed".into();
    event.observation_time = observed;
    event
}

#[test]
fn sentinel_and_keyset_continue_equal_times_without_skips_or_duplicates(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let events: Vec<_> = (1..=260).map(|n| observation(&store, n, 100)).collect();
    for batch in events.chunks(128) {
        store.append_batch(batch)?;
    }
    let expression = r#"sensor.id = "windows.observations""#;
    let first = store.observation_page(expression, None)?;
    assert_eq!(first.len(), 129);
    // The 129th result is a sentinel; only the first 128 were shown.
    let cursor = |event: &SecurityEvent| (event.observation_time, event.event_id);
    let second = store.observation_page(expression, Some(cursor(&first[127])))?;
    assert_eq!(second.len(), 129);
    assert_eq!(second[0].event_id, first[128].event_id);
    let third = store.observation_page(expression, Some(cursor(&second[127])))?;
    assert_eq!(third.len(), 4);
    let actual: Vec<_> = first[..128]
        .iter()
        .chain(&second[..128])
        .chain(&third)
        .map(|event| event.event_id)
        .collect();
    let expected: Vec<_> = events.iter().rev().map(|event| event.event_id).collect();
    assert_eq!(actual, expected);
    assert!(store
        .observation_page(expression, Some(cursor(third.last().unwrap())))?
        .is_empty());
    Ok(())
}

#[test]
fn observation_order_filter_and_cursor_use_observation_time() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let earlier_wall = observation(&store, 1, 300);
    let later_wall = observation(&store, 2, 100);
    store.append_batch(&[earlier_wall.clone(), later_wall.clone()])?;
    let page = store.observation_page("event.observed_at >= 100", None)?;
    assert_eq!(
        page.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![earlier_wall.event_id, later_wall.event_id]
    );
    let expression = "event.observed_at > 200 AND event.time < 10002";
    assert_eq!(
        store.observation_page(expression, None)?[0].event_id,
        earlier_wall.event_id
    );
    let query = EventQuery {
        expression: Some(expression.into()),
        ..Default::default()
    };
    assert_eq!(store.query(&query)?[0].event_id, earlier_wall.event_id);
    let continuation =
        store.observation_page("event.observed_at >= 100", Some((200, Uuid::nil())))?;
    assert_eq!(continuation.len(), 1);
    assert_eq!(continuation[0].event_id, later_wall.event_id);
    Ok(())
}

#[test]
fn parent_instance_filters_exact_identity_and_keeps_missing_unknown() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let parent = Uuid::from_u128(20);
    let mut child = observation(&store, 1, 100);
    child.parent_process = Some(ProcessContext {
        pid: 42,
        instance_id: Some(parent),
        name: Some("launcher.exe".into()),
        executable_path: None,
        creation_time_unix_ms: Some(10),
    });
    let absent = observation(&store, 2, 200);
    let mut other = observation(&store, 3, 300);
    other.parent_process = child.parent_process.clone();
    other.parent_process.as_mut().unwrap().instance_id = Some(Uuid::from_u128(21));
    store.append_batch(&[child.clone(), absent, other.clone()])?;
    let expression = format!("process.parent_instance = \"{parent}\"");
    assert_eq!(
        store
            .observation_page(&expression, None)?
            .iter()
            .map(|e| e.event_id)
            .collect::<Vec<_>>(),
        vec![child.event_id]
    );
    assert_eq!(
        store.query(&EventQuery {
            expression: Some(expression),
            ..Default::default()
        })?[0]
            .event_id,
        child.event_id
    );
    let negative = format!("process.parent_instance != \"{parent}\"");
    let page = store.observation_page(&negative, None)?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].event_id, other.event_id);
    Ok(())
}

#[test]
fn malformed_expressions_are_refused_and_sql_text_is_only_data() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let mut event = observation(&store, 1, 100);
    event.process.as_mut().unwrap().name = Some("x' OR 1=1 --".into());
    let ordinary = observation(&store, 2, 200);
    store.append_batch(&[event.clone(), ordinary])?;
    let injection = r#"process.name = "x' OR 1=1 --""#;
    let page = store.observation_page(injection, None)?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].event_id, event.event_id);
    for expression in [
        "",
        "event.observed_at = \"100\"",
        "process.parent_instance = 20",
        "event.observed_at >= 0; DROP TABLE events",
        "event.observed_at >= 0 OR 1=1",
    ] {
        assert!(matches!(
            store.observation_page(expression, None),
            Err(StorageError::QuerySyntax(_))
        ));
    }
    assert_eq!(store.count()?, 2);
    assert_eq!(store.verify_integrity()?.verified_events, 2);
    Ok(())
}

#[test]
fn oversized_page_returns_explicit_error_instead_of_partial_history() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let mut events: Vec<_> = (1..=70).map(|n| observation(&store, n, 100)).collect();
    for event in &mut events {
        event.process.as_mut().unwrap().executable_path = Some("x".repeat(64 * 1024));
    }
    for batch in events.chunks(16) {
        store.append_batch(batch)?;
    }
    assert!(matches!(
        store.observation_page("event.observed_at = 100", None),
        Err(StorageError::QueryResultTooLarge)
    ));
    assert_eq!(store.count()?, 70);
    Ok(())
}

#[test]
fn oversized_stored_row_is_refused_before_schema_decoding() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let mut store = directory.open()?;
    let event = observation(&store, 1, 100);
    store.append_batch(&[event])?;
    // A damaged archive may bypass the normal append/schema size gates.
    // Preserve valid JSON for SQLite's observation-time ordering, but omit
    // required schema fields so decoding would otherwise yield another error.
    let oversized = format!(
        "{{\"observation_time\":100,\"oversized\":\"{}\"}}",
        "x".repeat(4 * 1024 * 1024)
    );
    let connection = rusqlite::Connection::open(directory.0.join("events.sqlite3"))?;
    connection.execute("UPDATE events SET payload=?1", [oversized.as_bytes()])?;
    assert!(matches!(
        store.observation_page("event.observed_at = 100", None),
        Err(StorageError::QueryResultTooLarge)
    ));
    Ok(())
}
