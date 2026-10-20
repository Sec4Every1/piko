//! Read-only archive size/frequency audit, using the same SQLite as the service.
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::{
    error::Error,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: archive_noise DATABASE REPORT".into());
    }
    let db = Connection::open_with_flags(&args[1], OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_secs(2))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    db.progress_handler(10000, Some(move || Instant::now() >= deadline))?;
    let mut query = db.prepare("SELECT e.sensor_id,e.event_type,e.severity,count(*),sum(length(e.payload)),sum(coalesce(length(r.payload),0)),min(e.wall_time),max(e.wall_time) FROM events e LEFT JOIN raw_evidence r ON r.evidence_id=e.raw_evidence_id GROUP BY e.sensor_id,e.event_type,e.severity ORDER BY count(*) DESC")?;
    let groups: Vec<Value> = query.query_map([], |r| Ok(json!({
        "sensor":r.get::<_,String>(0)?,"type":r.get::<_,String>(1)?,"severity":r.get::<_,String>(2)?,
        "count":r.get::<_,u64>(3)?,"event_bytes":r.get::<_,u64>(4)?,"evidence_bytes":r.get::<_,u64>(5)?,
        "first_ms":r.get::<_,i64>(6)?,"last_ms":r.get::<_,i64>(7)?
    })))?.collect::<Result<_,_>>()?;
    let count: u64 = db.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
    let page_count: u64 = db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let page_size: u64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let free: u64 = db.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    // Only normalized targets for operational telemetry, no raw user payloads.
    let mut query = db.prepare("SELECT json_extract(CAST(payload AS TEXT),'$.target.kind'),json_extract(CAST(payload AS TEXT),'$.result'),count(*) FROM events WHERE event_type='telemetry.sensor_state' GROUP BY 1,2 ORDER BY count(*) DESC")?;
    let health:Vec<Value> = query.query_map([],|r|Ok(json!({"sensor":r.get::<_,Option<String>>(0)?,"state":r.get::<_,String>(1)?,"count":r.get::<_,u64>(2)?})))?.collect::<Result<_,_>>()?;
    let mut query=db.prepare("SELECT json_extract(CAST(payload AS TEXT),'$.process.name'),count(*) FROM events WHERE event_type='process.etw.started' GROUP BY 1 ORDER BY count(*) DESC LIMIT 20")?;
    let process_starts: Vec<Value> = query
        .query_map([], |r| {
            Ok(json!({"name":r.get::<_,Option<String>>(0)?,"count":r.get::<_,u64>(1)?}))
        })?
        .collect::<Result<_, _>>()?;
    let mut query=db.prepare("SELECT json_extract(CAST(payload AS TEXT),'$.target.identifier'),count(*) FROM events WHERE event_type='image.etw.loaded' GROUP BY 1 ORDER BY count(*) DESC LIMIT 15")?;
    let loaded_images: Vec<Value> = query
        .query_map([], |r| {
            Ok(json!({"path":r.get::<_,Option<String>>(0)?,"count":r.get::<_,u64>(1)?}))
        })?
        .collect::<Result<_, _>>()?;
    std::fs::write(
        &args[2],
        serde_json::to_vec_pretty(
            &json!({"count":count,"allocated_bytes":page_count*page_size,"active_bytes":(page_count-free)*page_size,"groups":groups,"health":health,"process_starts":process_starts,"loaded_images":loaded_images}),
        )?,
    )?;
    Ok(())
}
