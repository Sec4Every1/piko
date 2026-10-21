#![forbid(unsafe_code)]

mod evidence_codec;
mod identity_activity;
mod noise;
pub use identity_activity::{AuthenticationPage, AuthenticationQuery, AuthenticationRecord};
mod query_language;
mod retention;
pub use noise::NoiseCleanupReport;
pub use retention::calendar_cutoff;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use piko_event_schema::{
    EventRecord, RawEvidence, SchemaError, SecurityEvent, Severity, MAX_EVENT_BYTES,
    MAX_RAW_EVIDENCE_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_QUERY_LIMIT: usize = 1000;
pub const MAX_QUERY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BATCH_EVENTS: usize = 128;
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
// Automatic recovery must not turn one append into archive-scale maintenance.
const MAX_AUTOMATIC_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024;
const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub max_disk_bytes: u64,
    pub max_event_bytes: usize,
    pub retention_months: Option<u8>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_disk_bytes: 256 * 1024 * 1024,
            max_event_bytes: MAX_EVENT_BYTES,
            retention_months: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    pub limit: usize,
    pub event_type: Option<String>,
    pub severity: Option<Severity>,
    pub since_unix_ms: Option<i64>,
    pub search: Option<String>,
    pub expression: Option<String>,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            limit: 100,
            event_type: None,
            severity: None,
            since_unix_ms: None,
            search: None,
            expression: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntegrityReport {
    pub verified_events: u64,
    pub head_hash: Option<String>,
    /// False until an independently protected signed checkpoint is implemented.
    pub externally_anchored: bool,
    #[serde(default)]
    pub expired_events: u64,
}

pub trait EventStore {
    fn append_batch(&mut self, events: &[SecurityEvent]) -> Result<(), StorageError>;
    fn append_records(&mut self, records: &[EventRecord]) -> Result<(), StorageError>;
    fn query(&self, query: &EventQuery) -> Result<Vec<SecurityEvent>, StorageError>;
    fn verify_integrity(&self) -> Result<IntegrityReport, StorageError>;
    fn count(&self) -> Result<u64, StorageError>;
}

/// A single writer, durable local event store. Hash chaining is tamper evidence,
/// not authenticity: an administrator can rewrite the whole chain or its tail.
pub struct SqliteEventStore {
    connection: Connection,
    path: PathBuf,
    host_id: Uuid,
    config: StorageConfig,
}

struct PreparedRecord {
    event: SecurityEvent,
    payload: Vec<u8>,
    raw_payload: Option<Vec<u8>>,
    raw_digest: Option<[u8; 32]>,
}

impl SqliteEventStore {
    pub fn retention_months(&self) -> Option<u8> {
        self.config.retention_months
    }
    pub fn expired_events(&self) -> Result<u64, StorageError> {
        Ok(self.checkpoint()?.map_or(0, |c| c.position as u64))
    }
    /// Offline maintenance, at most 32 rows and 4 MiB original input per commit.
    /// Cursor is caller-owned: interrupted runs can safely restart from zero.
    pub fn compress_existing_evidence(
        &mut self,
        after: i64,
    ) -> Result<(i64, u64, u64, u64), StorageError> {
        if after < 0 {
            return Err(StorageError::Configuration);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut query = transaction.prepare("SELECT rowid, CASE WHEN length(payload)<=4194304 THEN payload ELSE NULL END,digest FROM raw_evidence WHERE rowid>?1 ORDER BY rowid LIMIT 32")?;
        let mut rows = query.query([after])?;
        let (mut cursor, mut scanned, mut saved, mut original_bytes) = (after, 0u64, 0u64, 0usize);
        let mut updates = Vec::new();
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let payload: Option<Vec<u8>> = row.get(1)?;
            let payload =
                payload.ok_or_else(|| StorageError::Corrupt("oversized evidence row".into()))?;
            // Already compressed records were verified by open(); skip without rewriting.
            if payload.starts_with(b"PIKOEV\x01") {
                cursor = id;
                scanned += 1;
                continue;
            }
            if original_bytes + payload.len() > MAX_BATCH_BYTES {
                break;
            }
            let logical = evidence_codec::decode(&payload)?;
            let digest: Vec<u8> = row.get(2)?;
            if Sha256::digest(&logical).as_slice() != digest.as_slice() {
                return Err(StorageError::Corrupt("raw evidence digest mismatch".into()));
            }
            let encoded = evidence_codec::encode(&logical)?;
            original_bytes += logical.len();
            cursor = id;
            scanned += 1;
            if encoded.len() < payload.len() {
                saved += (payload.len() - encoded.len()) as u64;
                updates.push((id, encoded));
            }
        }
        drop(rows);
        drop(query);
        let changed = updates.len() as u64;
        for (id, payload) in updates {
            transaction.execute(
                "UPDATE raw_evidence SET payload=?1 WHERE rowid=?2",
                params![payload, id],
            )?;
        }
        transaction.commit()?;
        Ok((cursor, scanned, changed, saved))
    }
    /// Read the latest *durable* sensor checkpoint from the hash-protected payload.
    /// open() verifies the chain before this is used to resume a source.
    pub fn latest_sensor_event(&self, sensor: &str) -> Result<Option<SecurityEvent>, StorageError> {
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT payload FROM events WHERE sensor_id=?1 ORDER BY position DESC LIMIT 1",
                [sensor],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|bytes| serde_json::from_slice(&bytes).map_err(StorageError::from))
            .transpose()
            .and_then(|event| match event {
                Some(event) => Ok(Some(event)),
                None => Ok(self
                    .checkpoint()?
                    .and_then(|c| c.bookmarks.get(sensor).cloned())),
            })
    }
    /// Existing archive only; no schema migration or journal/budget changes.
    pub fn reader(path: impl AsRef<Path>, config: StorageConfig) -> Result<Self, StorageError> {
        if config.max_disk_bytes < 8 * 1024 * 1024
            || config.max_disk_bytes > i64::MAX as u64
            || config
                .retention_months
                .is_some_and(|months| !(1..=120).contains(&months))
            || config.max_event_bytes == 0
            || config.max_event_bytes > MAX_EVENT_BYTES
        {
            return Err(StorageError::Configuration);
        }
        let path = path.as_ref().to_path_buf();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.is_symlink() {
            return Err(StorageError::Configuration);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(StorageError::Configuration);
            }
        }
        let connection = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_millis(500))?;
        let version: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='storage_version'",
            [],
            |r| r.get(0),
        )?;
        if version != "1" && version != "2" {
            return Err(StorageError::UnsupportedVersion(version));
        }
        let host: String =
            connection.query_row("SELECT value FROM metadata WHERE key='host_id'", [], |r| {
                r.get(0)
            })?;
        let host_id = Uuid::parse_str(&host)
            .map_err(|_| StorageError::Corrupt("invalid host identity".into()))?;
        if host_id.is_nil() {
            return Err(StorageError::Corrupt("nil host identity".into()));
        }
        let store = Self {
            connection,
            path,
            host_id,
            config,
        };
        store.check_budget(0)?;
        Ok(store)
    }

    pub fn open(path: impl AsRef<Path>, config: StorageConfig) -> Result<Self, StorageError> {
        if config.max_disk_bytes < 8 * 1024 * 1024
            || config.max_disk_bytes > i64::MAX as u64
            || config
                .retention_months
                .is_some_and(|months| !(1..=120).contains(&months))
            || config.max_event_bytes == 0
            || config.max_event_bytes > MAX_EVENT_BYTES
        {
            return Err(StorageError::Configuration);
        }
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(StorageError::Configuration);
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "wal_autocheckpoint", 256)?;
        connection.pragma_update(None, "journal_size_limit", 1024 * 1024)?;
        let page_size: u64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        // Reserve half the total budget for WAL/checkpoints and bounded overhead.
        connection.pragma_update(
            None,
            "max_page_count",
            config.max_disk_bytes / 2 / page_size,
        )?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS raw_evidence (
                 evidence_id TEXT PRIMARY KEY, payload BLOB NOT NULL, digest BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS events (
                 position INTEGER PRIMARY KEY,
                 event_id TEXT NOT NULL UNIQUE,
                 host_id TEXT NOT NULL,
                 runtime_instance_id TEXT NOT NULL,
                 sensor_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL CHECK(sequence > 0),
                 event_type TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 wall_time INTEGER NOT NULL,
                 payload BLOB NOT NULL,
                 previous_hash BLOB NOT NULL,
                 hash BLOB NOT NULL,
                 raw_evidence_id TEXT REFERENCES raw_evidence(evidence_id),
                 UNIQUE(host_id, runtime_instance_id, sensor_id, sequence)
             );
             CREATE INDEX IF NOT EXISTS events_type ON events(event_type, position);
             CREATE INDEX IF NOT EXISTS events_time ON events(wall_time);
             CREATE INDEX IF NOT EXISTS events_evidence ON events(raw_evidence_id);
             CREATE INDEX IF NOT EXISTS events_severity ON events(severity, position);",
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES('storage_version','1')",
            [],
        )?;
        let version: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='storage_version'",
            [],
            |row| row.get(0),
        )?;
        if version != "1" && version != "2" {
            return Err(StorageError::UnsupportedVersion(version));
        }
        connection.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES('host_id',?1)",
            [Uuid::new_v4().to_string()],
        )?;
        let host: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='host_id'",
            [],
            |row| row.get(0),
        )?;
        let host_id = Uuid::parse_str(&host)
            .map_err(|_| StorageError::Corrupt("invalid host identity".into()))?;
        if host_id.is_nil() {
            return Err(StorageError::Corrupt("nil host identity".into()));
        }
        let store = Self {
            connection,
            path,
            host_id,
            config,
        };
        store.check_budget(0)?;
        // Do not silently append after damage. Startup deliberately verifies all
        // evidence until independently anchored segments allow bounded checking.
        store.verify_integrity()?;
        store.connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS events_sensor_position ON events(sensor_id, position DESC); CREATE INDEX IF NOT EXISTS events_type_position ON events(event_type, position DESC)",
        )?;
        store.connection.execute_batch("CREATE TABLE IF NOT EXISTS detections(id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(event_id), payload BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS detections_event ON detections(event_id);")?;
        // Additive migration: historical evidence is evaluated too, without
        // re-ingestion or enforcement. Rule IDs make restart backfill idempotent.
        let mut query = store.connection.prepare("SELECT payload FROM events e WHERE event_type IN ('windows.event_log.1102','windows.event_log.104','windows.event_log.4719','windows.event_log.7045','windows.event_log.4720','windows.event_log.4732','windows.event_log.4698','windows.event_log.4702','windows.event_log.5001','windows.event_log.5007','windows.event_log.1116','windows.event_log.1117') AND NOT EXISTS (SELECT 1 FROM detections d WHERE d.event_id=e.event_id)")?;
        for row in query.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
            let event = SecurityEvent::decode(&row?)?;
            if let Some(alert) = piko_security_core::detect(&event) {
                store.check_budget(16384)?;
                store.connection.execute(
                    "INSERT OR IGNORE INTO detections(id,event_id,payload) VALUES(?1,?2,?3)",
                    params![
                        alert.id,
                        event.event_id.to_string(),
                        serde_json::to_vec(&alert)?
                    ],
                )?;
            }
        }
        drop(query);
        Ok(store)
    }

    pub fn alerts(&self) -> Result<Vec<piko_security_core::Alert>, StorageError> {
        // Regenerate explanatory data from hash-checked event payloads. The
        // derived index itself is not presented as independently authenticated.
        let mut query = self.connection.prepare("SELECT e.payload FROM detections d JOIN events e ON d.event_id=e.event_id ORDER BY e.position DESC LIMIT 100")?;
        let mut alerts = Vec::new();
        let mut bytes = 0;
        for row in query.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
            let event = SecurityEvent::decode(&row?)?;
            if let Some(mut alert) = piko_security_core::detect(&event) {
                let raw = event
                    .raw_evidence_reference
                    .map(|id| self.raw_evidence(id))
                    .transpose()?
                    .flatten();
                piko_security_core::assess(&mut alert, &event, raw.as_ref());
                // Bound enriched names as well as row count; reserve space for
                // the IPC envelope around the list.
                bytes += serde_json::to_vec(&alert)?.len();
                if bytes > MAX_QUERY_BYTES - 16 * 1024 {
                    return Err(StorageError::QueryResultTooLarge);
                }
                alerts.push(alert);
            }
        }
        alerts.extend(self.authentication_alerts()?);
        let mut positions = HashMap::new();
        for alert in &alerts {
            let position: i64 = self.connection.query_row(
                "SELECT position FROM events WHERE event_id=?1",
                [alert.event_id.to_string()],
                |r| r.get(0),
            )?;
            positions.insert(alert.event_id, position);
        }
        alerts.sort_by_key(|a| std::cmp::Reverse(positions[&a.event_id]));
        alerts.truncate(100);
        if serde_json::to_vec(&alerts)?.len() > MAX_QUERY_BYTES - 16 * 1024 {
            return Err(StorageError::QueryResultTooLarge);
        }
        Ok(alerts)
    }

    fn authentication_alerts(&self) -> Result<Vec<piko_security_core::Alert>, StorageError> {
        let mut query=self.connection.prepare("SELECT payload FROM events WHERE event_type='windows.event_log.4625' ORDER BY position DESC LIMIT 257")?;
        let mut events = Vec::new();
        let mut bytes = 0usize;
        for row in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let payload = row?;
            bytes = bytes.saturating_add(payload.len());
            if bytes > MAX_QUERY_BYTES {
                return Err(StorageError::QueryResultTooLarge);
            }
            events.push(SecurityEvent::decode(&payload)?);
        }
        // Drop the oldest, possibly clipped minute when the query reaches its bound.
        let cutoff = if events.len() > 256 {
            events.last().map(|e| e.wall_clock_time / 60000 * 60000)
        } else {
            None
        };
        events.truncate(256);
        let mut attempts = Vec::new();
        for event in events {
            if cutoff.is_some_and(|t| event.wall_clock_time / 60000 * 60000 <= t) {
                continue;
            }
            if let Some(id) = event.raw_evidence_reference {
                if let Some(raw) = self.raw_evidence(id)? {
                    bytes = bytes.saturating_add(raw.bytes.len());
                    if bytes > 16 * 1024 * 1024 {
                        return Err(StorageError::QueryResultTooLarge);
                    }
                    if let Some(attempt) = piko_security_core::failed_logon_attempt(&event, &raw) {
                        attempts.push(attempt);
                    }
                }
            }
        }
        Ok(piko_security_core::failed_logon_bursts(attempts))
    }

    pub fn host_id(&self) -> Uuid {
        self.host_id
    }

    /// Cooperative SQLite VM cancellation for an isolated storage worker. Clear
    /// this before durable writes: write acknowledgement must not be ambiguous.
    pub fn set_operation_deadline(&self, deadline: Option<Instant>) -> Result<(), StorageError> {
        match deadline {
            Some(deadline) => self
                .connection
                .progress_handler(1000, Some(move || Instant::now() >= deadline)),
            None => self.connection.progress_handler(0, None::<fn() -> bool>),
        }
        .map_err(StorageError::from)
    }
    pub fn count(&self) -> Result<u64, StorageError> {
        <Self as EventStore>::count(self)
    }
    pub fn append_batch(&mut self, events: &[SecurityEvent]) -> Result<(), StorageError> {
        <Self as EventStore>::append_batch(self, events)
    }
    pub fn append_records(&mut self, records: &[EventRecord]) -> Result<(), StorageError> {
        <Self as EventStore>::append_records(self, records)
    }
    pub fn query(&self, query: &EventQuery) -> Result<Vec<SecurityEvent>, StorageError> {
        <Self as EventStore>::query(self, query)
    }
    pub fn verify_integrity(&self) -> Result<IntegrityReport, StorageError> {
        <Self as EventStore>::verify_integrity(self)
    }

    pub fn raw_evidence(&self, id: Uuid) -> Result<Option<RawEvidence>, StorageError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT payload,digest FROM raw_evidence WHERE evidence_id=?1",
                [id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(payload, digest)| {
            let payload = evidence_codec::decode(&payload)?;
            if Sha256::digest(&payload).as_slice() != digest.as_slice() {
                return Err(StorageError::Corrupt("raw evidence digest mismatch".into()));
            }
            let raw: RawEvidence = serde_json::from_slice(&payload)?;
            if raw.evidence_id != id {
                return Err(StorageError::Corrupt(
                    "raw evidence identity mismatch".into(),
                ));
            }
            Ok(raw)
        })
        .transpose()
    }

    fn disk_bytes(&self) -> Result<u64, StorageError> {
        let mut total = 0_u64;
        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.path.as_os_str().to_os_string();
            name.push(suffix);
            match fs::metadata(PathBuf::from(name)) {
                Ok(metadata) => total = total.saturating_add(metadata.len()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(total)
    }

    /// Database bytes and aggregate database/WAL/SHM bytes, sampled on the storage worker.
    pub fn archive_bytes(&self) -> Result<(u64, u64), StorageError> {
        Ok((fs::metadata(&self.path)?.len(), self.disk_bytes()?))
    }

    /// Effective page limit on this SQLite connection, separate from the aggregate
    /// database/WAL/SHM disk budget. Reading it does not change either limit.
    pub fn database_limit_bytes(&self) -> Result<u64, StorageError> {
        let pages: u64 = self
            .connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))?;
        let size: u64 = self
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        pages
            .checked_mul(size)
            .filter(|bytes| *bytes > 0)
            .ok_or_else(|| StorageError::Corrupt("invalid SQLite page limit accounting".into()))
    }

    pub fn active_database_bytes(&self) -> Result<u64, StorageError> {
        let pages: u64 = self
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))?;
        let free: u64 = self
            .connection
            .pragma_query_value(None, "freelist_count", |row| row.get(0))?;
        let size: u64 = self
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        pages
            .checked_sub(free)
            .and_then(|used| used.checked_mul(size))
            .ok_or_else(|| StorageError::Corrupt("invalid SQLite page accounting".into()))
    }

    fn check_budget(&self, estimated_growth: u64) -> Result<(), StorageError> {
        if self.disk_bytes()?.saturating_add(estimated_growth) > self.config.max_disk_bytes {
            return Err(StorageError::DiskBudgetExceeded);
        }
        Ok(())
    }

    fn pending_checkpoint_growth(&self) -> Result<u64, StorageError> {
        // Include freelist pages: checkpoint writes allocated pages, not just
        // currently active records. WAL truncation happens after main-file growth.
        let pages: u64 = self
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))?;
        let size: u64 = self
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        let logical_bytes = pages
            .checked_mul(size)
            .ok_or_else(|| StorageError::Corrupt("invalid SQLite page accounting".into()))?;
        Ok(logical_bytes.saturating_sub(fs::metadata(&self.path)?.len()))
    }

    fn ensure_append_budget(&self, estimated_growth: u64) -> Result<(), StorageError> {
        let pending = self.pending_checkpoint_growth()?;
        match self.check_budget(estimated_growth.saturating_add(pending)) {
            Ok(()) => return Ok(()),
            Err(StorageError::DiskBudgetExceeded) => {}
            Err(error) => return Err(error),
        }
        // A released reader can leave a large physical WAL that prevents all
        // future commits. Reclaim it only if simultaneous main/WAL allocation fits.
        self.check_budget(pending)?;
        let mut wal = self.path.as_os_str().to_os_string();
        wal.push("-wal");
        let wal_bytes = match fs::metadata(PathBuf::from(wal)) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        if wal_bytes == 0
            || wal_bytes > MAX_AUTOMATIC_CHECKPOINT_BYTES
            || pending > MAX_AUTOMATIC_CHECKPOINT_BYTES
        {
            return Err(StorageError::DiskBudgetExceeded);
        }
        let previous_timeout: u64 =
            self.connection
                .pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
        self.connection.busy_timeout(Duration::ZERO)?;
        let checkpoint = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            });
        // Restore connection policy on both success and SQLite error.
        self.connection
            .busy_timeout(Duration::from_millis(previous_timeout))?;
        let (busy, _, _) = checkpoint?;
        if busy != 0 {
            return Err(StorageError::DiskBudgetExceeded);
        }
        self.check_budget(estimated_growth.saturating_add(self.pending_checkpoint_growth()?))
    }
}

impl EventStore for SqliteEventStore {
    fn append_batch(&mut self, events: &[SecurityEvent]) -> Result<(), StorageError> {
        if events.len() > MAX_BATCH_EVENTS {
            return Err(StorageError::BatchTooLarge);
        }
        let records: Vec<_> = events
            .iter()
            .cloned()
            .map(|event| EventRecord {
                event,
                raw_evidence: None,
            })
            .collect();
        self.append_records(&records)
    }

    fn append_records(&mut self, records: &[EventRecord]) -> Result<(), StorageError> {
        if records.len() > MAX_BATCH_EVENTS {
            return Err(StorageError::BatchTooLarge);
        }
        if records.is_empty() {
            return Ok(());
        }
        let mut prepared = Vec::with_capacity(records.len());
        let mut total_bytes = 0_usize;
        let mut original_bytes = 0_usize;
        for record in records {
            record.event.validate().map_err(|error| match error {
                SchemaError::TooLarge => StorageError::EventTooLarge,
                other => StorageError::Schema(other),
            })?;
            if record.event.host_id != self.host_id {
                return Err(StorageError::HostMismatch);
            }
            let payload = serde_json::to_vec(&record.event)?;
            if payload.len() > self.config.max_event_bytes {
                return Err(StorageError::EventTooLarge);
            }
            let raw_payload = match (&record.event.raw_evidence_reference, &record.raw_evidence) {
                (None, None) => None,
                (Some(id), Some(raw)) if *id == raw.evidence_id => {
                    if raw.evidence_id.is_nil()
                        || raw.bytes.len() > MAX_RAW_EVIDENCE_BYTES
                        || raw.source.is_empty()
                        || raw.source.len() > 256
                        || raw.content_type.is_empty()
                        || raw.content_type.len() > 128
                        || raw.observed_at_unix_ms < 0
                    {
                        return Err(StorageError::InvalidRawEvidence);
                    }
                    Some(serde_json::to_vec(raw)?)
                }
                _ => return Err(StorageError::InvalidRawEvidence),
            };
            let raw_digest = raw_payload
                .as_ref()
                .map(|bytes| Sha256::digest(bytes).into());
            original_bytes = original_bytes
                .saturating_add(payload.len())
                .saturating_add(raw_payload.as_ref().map_or(0, Vec::len));
            if original_bytes > MAX_BATCH_BYTES {
                return Err(StorageError::BatchTooLarge);
            }
            let raw_payload = raw_payload
                .as_deref()
                .map(evidence_codec::encode)
                .transpose()?;
            total_bytes = total_bytes
                .saturating_add(payload.len())
                .saturating_add(raw_payload.as_ref().map_or(0, Vec::len));
            if total_bytes > MAX_BATCH_BYTES {
                return Err(StorageError::BatchTooLarge);
            }
            prepared.push(PreparedRecord {
                event: record.event.clone(),
                payload,
                raw_payload,
                raw_digest,
            });
        }
        // Conservative accounting includes index and WAL page amplification.
        self.ensure_append_budget(
            (total_bytes as u64)
                .saturating_mul(4)
                .saturating_add(records.len() as u64 * 16_384)
                .saturating_add(65_536),
        )?;
        let checkpoint = self.checkpoint()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT position,hash FROM events ORDER BY position DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (mut position, mut previous) = head.unwrap_or_else(|| {
            checkpoint
                .as_ref()
                .map_or((0, ZERO_HASH.to_vec()), |c| (c.position, c.hash.clone()))
        });
        for record in prepared {
            let last_sequence: Option<i64> = transaction.query_row(
                "SELECT MAX(sequence) FROM events WHERE host_id=?1 AND runtime_instance_id=?2 AND sensor_id=?3",
                params![record.event.host_id.to_string(), record.event.runtime_instance_id.to_string(), record.event.sensor_id],
                |row| row.get(0),
            )?;
            if last_sequence.is_some_and(|last| record.event.sequence <= last as u64) {
                return Err(StorageError::SequenceRegression);
            }
            if checkpoint
                .as_ref()
                .and_then(|c| c.watermarks.get(&retention::key(&record.event)))
                .is_some_and(|last| record.event.sequence <= *last)
            {
                return Err(StorageError::SequenceRegression);
            }
            position = position
                .checked_add(1)
                .ok_or(StorageError::SequenceExhausted)?;
            let hash = record_hash(
                position,
                &previous,
                &record.payload,
                record.raw_digest.as_ref(),
            );
            if let (Some(raw_payload), Some(raw_digest), Some(id)) = (
                record.raw_payload,
                record.raw_digest,
                record.event.raw_evidence_reference,
            ) {
                transaction.execute(
                    "INSERT INTO raw_evidence(evidence_id,payload,digest) VALUES(?1,?2,?3)",
                    params![id.to_string(), raw_payload, raw_digest.as_slice()],
                )?;
            }
            transaction.execute(
                "INSERT INTO events(position,event_id,host_id,runtime_instance_id,sensor_id,sequence,event_type,severity,wall_time,payload,previous_hash,hash,raw_evidence_id)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![position, record.event.event_id.to_string(), record.event.host_id.to_string(),
                    record.event.runtime_instance_id.to_string(), record.event.sensor_id,
                    record.event.sequence as i64, record.event.event_type, record.event.severity.as_str(),
                    record.event.wall_clock_time, record.payload, previous, hash.as_slice(),
                    record.event.raw_evidence_reference.map(|id| id.to_string())],
            )?;
            if let Some(alert) = piko_security_core::detect(&record.event) {
                transaction.execute(
                    "INSERT INTO detections(id,event_id,payload) VALUES(?1,?2,?3)",
                    params![
                        alert.id,
                        record.event.event_id.to_string(),
                        serde_json::to_vec(&alert)?
                    ],
                )?;
            }
            previous = hash.to_vec();
        }
        transaction.commit()?;
        Ok(())
    }

    fn query(&self, query: &EventQuery) -> Result<Vec<SecurityEvent>, StorageError> {
        if query.limit == 0
            || query.limit > MAX_QUERY_LIMIT
            || query.search.as_ref().is_some_and(|value| value.len() > 256)
            || query
                .event_type
                .as_ref()
                .is_some_and(|value| value.len() > 128)
            || query.since_unix_ms.is_some_and(|value| value < 0)
        {
            return Err(StorageError::InvalidQuery);
        }
        use rusqlite::types::Value;
        let mut values = vec![
            query.event_type.clone().map_or(Value::Null, Value::Text),
            query
                .severity
                .map(|v| Value::Text(v.as_str().into()))
                .unwrap_or(Value::Null),
            query.since_unix_ms.map_or(Value::Null, Value::Integer),
            query.search.clone().map_or(Value::Null, Value::Text),
            Value::Integer(query.limit as i64),
        ];
        let expression = query
            .expression
            .as_deref()
            .map(|input| query_language::compile(input, &mut values))
            .transpose()
            .map_err(|e| StorageError::QuerySyntax(e.to_string()))?
            .unwrap_or_else(|| "1".into());
        let sql = format!(
            "SELECT payload FROM events WHERE (?1 IS NULL OR event_type=?1)
             AND (?2 IS NULL OR severity=?2) AND (?3 IS NULL OR wall_time>=?3)
             AND (?4 IS NULL OR instr(lower(CAST(payload AS TEXT)),lower(?4))>0)
             AND ({expression}) ORDER BY position DESC LIMIT ?5"
        );
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut total_bytes = 0_usize;
        let mut events = Vec::new();
        for row in rows {
            let payload = row?;
            total_bytes = total_bytes.saturating_add(payload.len());
            if total_bytes > MAX_QUERY_BYTES {
                return Err(StorageError::QueryResultTooLarge);
            }
            events.push(SecurityEvent::decode(&payload)?);
        }
        Ok(events)
    }

    fn verify_integrity(&self) -> Result<IntegrityReport, StorageError> {
        // Keep quick_check, chain/index/raw and orphan checks in one WAL read snapshot.
        let _snapshot = if self.connection.is_autocommit() {
            Some(self.connection.unchecked_transaction()?)
        } else {
            None
        };
        let check: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if check != "ok" {
            return Err(StorageError::Corrupt(check));
        }
        let mut statement = self.connection.prepare(
            "SELECT e.position,e.payload,e.previous_hash,e.hash,e.event_id,e.host_id,e.runtime_instance_id,
                    e.sensor_id,e.sequence,e.event_type,e.severity,e.wall_time,e.raw_evidence_id,r.payload,r.digest
             FROM events e LEFT JOIN raw_evidence r ON r.evidence_id=e.raw_evidence_id ORDER BY e.position",
        )?;
        let mut rows = statement.query([])?;
        let checkpoint = self.checkpoint()?;
        let expired = checkpoint.as_ref().map_or(0, |c| c.position as u64);
        let mut expected_position = checkpoint.as_ref().map_or(Ok(1_i64), |c| {
            c.position
                .checked_add(1)
                .ok_or(StorageError::SequenceExhausted)
        })?;
        let mut previous = checkpoint
            .as_ref()
            .map_or_else(|| ZERO_HASH.to_vec(), |c| c.hash.clone());
        let mut sequences: HashMap<(Uuid, String), u64> = HashMap::new();
        if let Some(c) = checkpoint {
            for (key, value) in c.watermarks {
                let (id, sensor) = key.split_once('/').ok_or(StorageError::Configuration)?;
                sequences.insert(
                    (
                        Uuid::parse_str(id).map_err(|_| StorageError::Configuration)?,
                        sensor.into(),
                    ),
                    value,
                );
            }
        }
        while let Some(row) = rows.next()? {
            let position: i64 = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            let stored_previous: Vec<u8> = row.get(2)?;
            let stored_hash: Vec<u8> = row.get(3)?;
            if position != expected_position || stored_previous != previous {
                return Err(StorageError::Corrupt(format!(
                    "chain gap at position {position}"
                )));
            }
            let event = SecurityEvent::decode(&payload)?;
            let raw_id: Option<String> = row.get(12)?;
            if event.event_id.to_string() != row.get::<_, String>(4)?
                || event.host_id != self.host_id
                || event.host_id.to_string() != row.get::<_, String>(5)?
                || event.runtime_instance_id.to_string() != row.get::<_, String>(6)?
                || event.sensor_id != row.get::<_, String>(7)?
                || event.sequence != row.get::<_, i64>(8)? as u64
                || event.event_type != row.get::<_, String>(9)?
                || event.severity.as_str() != row.get::<_, String>(10)?
                || event.wall_clock_time != row.get::<_, i64>(11)?
                || event.raw_evidence_reference.map(|id| id.to_string()) != raw_id
            {
                return Err(StorageError::Corrupt(format!(
                    "index/payload mismatch at position {position}"
                )));
            }
            let key = (event.runtime_instance_id, event.sensor_id.clone());
            if sequences
                .get(&key)
                .is_some_and(|last| event.sequence <= *last)
            {
                return Err(StorageError::Corrupt(format!(
                    "sequence regression at position {position}"
                )));
            }
            sequences.insert(key, event.sequence);
            let raw_digest: Option<[u8; 32]> = match event.raw_evidence_reference {
                Some(id) => {
                    let raw_payload: Option<Vec<u8>> = row.get(13)?;
                    let digest: Option<Vec<u8>> = row.get(14)?;
                    let raw_payload = raw_payload
                        .ok_or_else(|| StorageError::Corrupt("missing raw evidence".into()))?;
                    let raw_payload = evidence_codec::decode(&raw_payload)?;
                    let computed: [u8; 32] = Sha256::digest(&raw_payload).into();
                    if digest.as_deref() != Some(computed.as_slice()) {
                        return Err(StorageError::Corrupt("raw evidence hash mismatch".into()));
                    }
                    let raw: RawEvidence = serde_json::from_slice(&raw_payload)?;
                    if raw.evidence_id != id {
                        return Err(StorageError::Corrupt(
                            "raw evidence identity mismatch".into(),
                        ));
                    }
                    Some(computed)
                }
                None => None,
            };
            let expected_hash = record_hash(position, &previous, &payload, raw_digest.as_ref());
            if expected_hash.as_slice() != stored_hash.as_slice() {
                return Err(StorageError::Corrupt(format!(
                    "hash mismatch at position {position}"
                )));
            }
            previous = stored_hash;
            expected_position = expected_position
                .checked_add(1)
                .ok_or(StorageError::SequenceExhausted)?;
        }
        let orphan_count: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM raw_evidence r WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.raw_evidence_id=r.evidence_id)", [], |row| row.get(0),
        )?;
        if orphan_count != 0 {
            return Err(StorageError::Corrupt("unreferenced raw evidence".into()));
        }
        Ok(IntegrityReport {
            verified_events: (expected_position - 1) as u64 - expired,
            head_hash: if expected_position == 1 {
                None
            } else {
                Some(hex(&previous))
            },
            externally_anchored: false,
            expired_events: expired,
        })
    }

    fn count(&self) -> Result<u64, StorageError> {
        Ok(self
            .connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?)
    }
}

fn record_hash(
    position: i64,
    previous: &[u8],
    payload: &[u8],
    raw_digest: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"piko-event-chain-v1\0");
    hash.update(position.to_le_bytes());
    hash.update(previous);
    hash.update((payload.len() as u64).to_le_bytes());
    hash.update(payload);
    hash.update([u8::from(raw_digest.is_some())]);
    if let Some(raw) = raw_digest {
        hash.update(raw);
    }
    hash.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid storage configuration")]
    Configuration,
    #[error("unsupported storage schema version: {0}")]
    UnsupportedVersion(String),
    #[error("storage budget exhausted; batch was not accepted")]
    DiskBudgetExceeded,
    #[error("event exceeds configured size limit")]
    EventTooLarge,
    #[error("batch exceeds 128 events or 4 MiB")]
    BatchTooLarge,
    #[error("event host differs from this local store")]
    HostMismatch,
    #[error("sequence is not increasing within the sensor runtime")]
    SequenceRegression,
    #[error("storage sequence exhausted")]
    SequenceExhausted,
    #[error("raw evidence is invalid, too large, or not attached to its event")]
    InvalidRawEvidence,
    #[error("invalid bounded event query")]
    InvalidQuery,
    #[error("{0}")]
    QuerySyntax(String),
    #[error("query result exceeds 4 MiB; reduce the limit or narrow filters")]
    QueryResultTooLarge,
    #[error("evidence corruption: {0}")]
    Corrupt(String),
    #[error("event schema error: {0}")]
    Schema(#[from] SchemaError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("evidence JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_restores_busy_timeout_on_reader_busy_and_sqlite_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path =
            std::env::temp_dir().join(format!("piko-checkpoint-timeout-{}.db", Uuid::new_v4()));
        let mut store = SqliteEventStore::open(
            &path,
            StorageConfig {
                max_disk_bytes: 8 * 1024 * 1024,
                ..Default::default()
            },
        )?;
        let runtime = Uuid::new_v4();
        store.append_batch(&[SecurityEvent::heartbeat(
            store.host_id(),
            runtime,
            1,
            100,
            1,
        )])?;
        store.connection.busy_timeout(Duration::from_millis(137))?;
        let reader =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let pinned = reader.unchecked_transaction()?;
        let _: u64 = pinned.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        store.append_batch(&[SecurityEvent::heartbeat(
            store.host_id(),
            runtime,
            2,
            100,
            2,
        )])?;
        let before = store.verify_integrity()?;
        // Oversized estimate forces the checkpoint branch without adding records.
        let oversized = store.config.max_disk_bytes;
        assert!(matches!(
            store.ensure_append_budget(oversized),
            Err(StorageError::DiskBudgetExceeded)
        ));
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "busy_timeout", |r| r.get::<_, u64>(0))?,
            137
        );
        pinned.rollback()?;
        drop(reader);
        assert!(matches!(
            store.ensure_append_budget(oversized),
            Err(StorageError::DiskBudgetExceeded)
        ));
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "busy_timeout", |r| r.get::<_, u64>(0))?,
            137
        );
        assert_eq!(store.verify_integrity()?, before);

        store.append_batch(&[SecurityEvent::heartbeat(
            store.host_id(),
            runtime,
            3,
            100,
            3,
        )])?;
        let before = store.verify_integrity()?;
        let own_snapshot = store.connection.unchecked_transaction()?;
        let _: u64 = own_snapshot.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        assert!(matches!(
            store.ensure_append_budget(oversized),
            Err(StorageError::Sqlite(_))
        ));
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "busy_timeout", |r| r.get::<_, u64>(0))?,
            137
        );
        own_snapshot.rollback()?;
        assert_eq!(store.verify_integrity()?, before);
        drop(store);
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn database_limit_reports_effective_connection_pragma_without_changing_integrity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let fixture = Fixture(
            std::env::temp_dir().join(format!("piko-effective-page-limit-{}", Uuid::new_v4())),
        );
        fs::create_dir(&fixture.0)?;
        let config = StorageConfig {
            max_disk_bytes: 8 * 1024 * 1024,
            ..Default::default()
        };
        let mut store = SqliteEventStore::open(fixture.0.join("events.db"), config.clone())?;
        let page_size: u64 = store
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        assert_eq!(store.verify_integrity()?.verified_events, 0);
        let initial = store.database_limit_bytes()?;
        assert_eq!(initial, config.max_disk_bytes / 2 / page_size * page_size);
        let reduced_pages = initial / page_size / 2;
        store
            .connection
            .pragma_update(None, "max_page_count", reduced_pages)?;
        let reduced = store.database_limit_bytes()?;
        assert_eq!(reduced, reduced_pages * page_size);
        assert!(reduced < initial);
        let before = store.verify_integrity()?;
        let event = SecurityEvent::heartbeat(store.host_id(), Uuid::new_v4(), 1, 100, 1);
        store.append_batch(&[event])?;
        let after = store.verify_integrity()?;
        assert_eq!(before.verified_events, 0);
        assert_eq!(after.verified_events, 1);
        assert!(after.head_hash.is_some());
        assert_eq!(store.database_limit_bytes()?, reduced);
        assert_eq!(store.verify_integrity()?, after);
        Ok(())
    }
}
