//! Explicit prefix expiry by ingestion time. Checkpoints are local, not signed.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub host: Uuid,
    pub position: i64,
    pub hash: Vec<u8>,
    pub cutoff_unix_ms: i64,
    pub watermarks: BTreeMap<String, u64>,
    pub bookmarks: BTreeMap<String, SecurityEvent>,
}
pub(crate) fn key(event: &SecurityEvent) -> String {
    format!("{}/{}", event.runtime_instance_id, event.sensor_id)
}
pub fn calendar_cutoff(now_ms: i64, months: u8) -> Result<i64, StorageError> {
    if !(1..=120).contains(&months) || now_ms < 0 {
        return Err(StorageError::Configuration);
    }
    let now = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
        .map_err(|_| StorageError::Configuration)?;
    let index = now.year() * 12 + i32::from(u8::from(now.month())) - 1 - i32::from(months);
    let year = index.div_euclid(12);
    let month = time::Month::try_from((index.rem_euclid(12) + 1) as u8)
        .map_err(|_| StorageError::Configuration)?;
    let mut day = now.day();
    let date = loop {
        match time::Date::from_calendar_date(year, month, day) {
            Ok(d) => break d,
            Err(_) if day > 1 => day -= 1,
            Err(_) => return Err(StorageError::Configuration),
        }
    };
    i64::try_from(
        date.with_time(now.time())
            .assume_utc()
            .unix_timestamp_nanos()
            / 1_000_000,
    )
    .map_err(|_| StorageError::Configuration)
}

impl SqliteEventStore {
    pub(crate) fn checkpoint(&self) -> Result<Option<Checkpoint>, StorageError> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM metadata WHERE key='retention_checkpoint'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let version: String = self.connection.query_row(
            "SELECT value FROM metadata WHERE key='storage_version'",
            [],
            |r| r.get(0),
        )?;
        let Some(raw) = raw else {
            return if version == "2" {
                Err(StorageError::Corrupt("missing retention checkpoint".into()))
            } else {
                Ok(None)
            };
        };
        if version != "2" {
            return Err(StorageError::Corrupt("checkpoint/version mismatch".into()));
        }
        if raw.len() > MAX_QUERY_BYTES {
            return Err(StorageError::Corrupt(
                "oversized retention checkpoint".into(),
            ));
        }
        let digest: String = self.connection.query_row(
            "SELECT value FROM metadata WHERE key='retention_checkpoint_digest'",
            [],
            |r| r.get(0),
        )?;
        if digest != hex(&Sha256::digest(raw.as_bytes())) {
            return Err(StorageError::Corrupt(
                "retention checkpoint digest mismatch".into(),
            ));
        }
        let checkpoint: Checkpoint = serde_json::from_str(&raw)?;
        if checkpoint.host != self.host_id
            || checkpoint.position <= 0
            || checkpoint.hash.len() != 32
            || checkpoint.watermarks.len() > 4096
            || checkpoint.bookmarks.len() > 16
        {
            return Err(StorageError::Corrupt("invalid retention checkpoint".into()));
        }
        for (key, value) in &checkpoint.watermarks {
            if key.len() > 600
                || key.len() < 38
                || key
                    .get(..36)
                    .and_then(|v| Uuid::parse_str(v).ok())
                    .is_none()
                || key.as_bytes()[36] != b'/'
                || *value == 0
                || *value > i64::MAX as u64
            {
                return Err(StorageError::Corrupt("invalid retention watermark".into()));
            }
        }
        for (sensor, event) in &checkpoint.bookmarks {
            event.validate()?;
            if sensor != &event.sensor_id
                || event.host_id != self.host_id
                || event
                    .integrity_metadata
                    .source_integrity
                    .as_ref()
                    .is_none_or(|v| v.len() > 8192)
            {
                return Err(StorageError::Corrupt(
                    "invalid retained source bookmark".into(),
                ));
            }
        }
        Ok(Some(checkpoint))
    }

    /// Expire only a contiguous, verified old prefix. Never cross a recent record.
    /// Each atomic step is bounded to 32 records / 4 MiB decoded evidence.
    pub fn expire_before(&mut self, cutoff: i64) -> Result<u64, StorageError> {
        let mut checkpoint = self.checkpoint()?.unwrap_or(Checkpoint {
            host: self.host_id,
            position: 0,
            hash: ZERO_HASH.to_vec(),
            cutoff_unix_ms: cutoff,
            watermarks: BTreeMap::new(),
            bookmarks: BTreeMap::new(),
        });
        // Clock rollback must not move an existing policy checkpoint backwards.
        if cutoff < checkpoint.cutoff_unix_ms {
            return Ok(0);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut query=transaction.prepare("SELECT e.position,e.payload,e.previous_hash,e.hash,e.event_id,e.host_id,e.runtime_instance_id,e.sensor_id,e.sequence,e.event_type,e.severity,e.wall_time,e.raw_evidence_id,r.payload,r.digest FROM events e LEFT JOIN raw_evidence r ON r.evidence_id=e.raw_evidence_id ORDER BY e.position LIMIT 32")?;
        let mut rows = query.query([])?;
        let (mut count, mut bytes) = (0u64, 0usize);
        let mut raw_ids = Vec::new();
        while let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(1)?;
            let event = SecurityEvent::decode(&payload)?;
            if event.ingestion_time >= cutoff {
                break;
            }
            let position: i64 = row.get(0)?;
            let previous: Vec<u8> = row.get(2)?;
            let hash: Vec<u8> = row.get(3)?;
            let raw_id: Option<String> = row.get(12)?;
            if position
                != checkpoint
                    .position
                    .checked_add(1)
                    .ok_or(StorageError::SequenceExhausted)?
                || previous != checkpoint.hash
                || event.event_id.to_string() != row.get::<_, String>(4)?
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
                return Err(StorageError::Corrupt("invalid event before expiry".into()));
            }
            let raw_digest = if let Some(id) = event.raw_evidence_reference {
                let encoded: Option<Vec<u8>> = row.get(13)?;
                let decoded =
                    evidence_codec::decode(&encoded.ok_or(StorageError::InvalidRawEvidence)?)?;
                bytes = bytes.saturating_add(decoded.len());
                let digest: [u8; 32] = Sha256::digest(&decoded).into();
                let stored: Option<Vec<u8>> = row.get(14)?;
                let raw: RawEvidence = serde_json::from_slice(&decoded)?;
                if stored.as_deref() != Some(digest.as_slice()) || raw.evidence_id != id {
                    return Err(StorageError::Corrupt(
                        "invalid evidence before expiry".into(),
                    ));
                }
                Some(digest)
            } else {
                None
            };
            bytes = bytes.saturating_add(payload.len());
            if bytes > MAX_BATCH_BYTES {
                break;
            }
            if record_hash(position, &previous, &payload, raw_digest.as_ref()).as_slice() != hash {
                return Err(StorageError::Corrupt("invalid chain before expiry".into()));
            }
            let watermark = checkpoint.watermarks.entry(key(&event)).or_default();
            if event.sequence <= *watermark {
                return Err(StorageError::SequenceRegression);
            }
            *watermark = event.sequence;
            if event.integrity_metadata.source_integrity.is_some() {
                checkpoint.bookmarks.insert(event.sensor_id.clone(), event);
            }
            if let Some(id) = raw_id {
                raw_ids.push(id);
            }
            checkpoint.position = position;
            checkpoint.hash = hash;
            count += 1;
        }
        drop(rows);
        drop(query);
        if count == 0 {
            return Ok(0);
        }
        checkpoint.cutoff_unix_ms = cutoff;
        if checkpoint.watermarks.len() > 4096 || checkpoint.bookmarks.len() > 16 {
            return Err(StorageError::Configuration);
        }
        let json = serde_json::to_string(&checkpoint)?;
        if json.len() > MAX_QUERY_BYTES {
            return Err(StorageError::Configuration);
        }
        transaction.execute("DELETE FROM detections WHERE event_id IN (SELECT event_id FROM events WHERE position<=?1)",[checkpoint.position])?;
        transaction.execute(
            "DELETE FROM events WHERE position<=?1",
            [checkpoint.position],
        )?;
        for id in raw_ids {
            transaction.execute("DELETE FROM raw_evidence WHERE evidence_id=?1 AND NOT EXISTS(SELECT 1 FROM events WHERE raw_evidence_id=?1)",[id])?;
        }
        transaction.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES('retention_checkpoint',?1)",
            [&json],
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES('retention_checkpoint_digest',?1)",
            [hex(&Sha256::digest(json.as_bytes()))],
        )?;
        transaction.execute(
            "UPDATE metadata SET value='2' WHERE key='storage_version'",
            [],
        )?;
        transaction.commit()?;
        Ok(count)
    }
}
