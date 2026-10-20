//! Small reproducible smoke benchmark; not a product performance guarantee.
use std::error::Error;
use std::fs;
use std::time::Instant;

use piko_event_schema::SecurityEvent;
use piko_event_storage::{EventQuery, SqliteEventStore, StorageConfig};
use serde_json::json;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!("piko-benchmark-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory)?;
    let mut store =
        SqliteEventStore::open(directory.join("events.sqlite3"), StorageConfig::default())?;
    let runtime = Uuid::new_v4();
    let total = 5000_u64;
    let started = Instant::now();
    for first in (1..=total).step_by(100) {
        let batch: Vec<_> = (first..first + 100)
            .map(|sequence| {
                SecurityEvent::heartbeat(
                    store.host_id(),
                    runtime,
                    sequence,
                    1_700_000_000_000,
                    sequence * 1000,
                )
            })
            .collect();
        store.append_batch(&batch)?;
    }
    let append_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let report = store.verify_integrity()?;
    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let events = store.query(&EventQuery {
        limit: 100,
        search: Some("heartbeat".into()),
        ..EventQuery::default()
    })?;
    let query_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let no_matches = store.query(&EventQuery {
        search: Some("no-match-full-scan-benchmark".into()),
        ..EventQuery::default()
    })?;
    let query_full_scan_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "events": total,
            "batch_size": 100,
            "append_seconds": append_seconds,
            "events_per_second": total as f64 / append_seconds,
            "verify_ms": verify_ms,
            "verified_events": report.verified_events,
            "query_limit": events.len(),
            "query_ms": query_ms,
        "query_full_scan_ms": query_full_scan_ms,
        "query_full_scan_matches": no_matches.len(),
            "storage": "SQLite WAL synchronous FULL; synthetic runtime heartbeat records"
        }))?
    );
    drop(store);
    fs::remove_dir_all(directory)?;
    Ok(())
}
