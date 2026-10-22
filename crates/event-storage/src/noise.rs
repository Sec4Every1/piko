//! Explicit offline rewrite: preserve security payloads, create a new local chain.
use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct NoiseCleanupReport {
    pub policy: String,
    pub before: IntegrityReport,
    pub after: IntegrityReport,
    pub removed: BTreeMap<String, u64>,
    pub chain_rebuilt: bool,
}

impl SqliteEventStore {
    /// Creates a separate verified archive; never changes the source. The caller
    /// must stop writers, preserve a protected backup and atomically replace it.
    pub fn copy_without_noise(
        &self,
        destination: &Path,
    ) -> Result<NoiseCleanupReport, StorageError> {
        // Writers must be stopped by the maintenance caller. Verification and
        // copying share one stable read snapshot, including raw evidence.
        let _snapshot = self.connection.unchecked_transaction()?;
        let before = self.verify_integrity()?;
        if destination.exists() {
            return Err(StorageError::Configuration);
        }
        // Fail closed on an already expired archive until a dedicated transition
        // can preserve its prior checkpoint and lifetime counters.
        if self.checkpoint()?.is_some() {
            return Err(StorageError::Configuration);
        }
        let mut target = Self::open(destination, self.config.clone())?;
        target.connection.execute(
            "UPDATE metadata SET value=?1 WHERE key='host_id'",
            [self.host_id.to_string()],
        )?;
        target.host_id = self.host_id;
        let mut query = self
            .connection
            .prepare("SELECT payload FROM events ORDER BY position")?;
        let mut rows = query.query([])?;
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        let mut removed = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            let event = SecurityEvent::decode(&bytes)?;
            let removable = event.severity == Severity::Info
                && ((event.sensor_id == "piko.runtime" && event.event_type == "runtime.heartbeat")
                    || (event.sensor_id == "windows.etw.process_image"
                        && event.event_type == "image.etw.unloaded"
                        && event.result == "observed"));
            // Never remove an event referenced by a detection, even if a future
            // rule uses a type this policy currently treats as operational noise.
            let has_detection: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM detections WHERE event_id=?1)",
                [event.event_id.to_string()],
                |r| r.get(0),
            )?;
            if removable && !has_detection {
                *removed.entry(event.event_type.clone()).or_default() += 1;
                continue;
            }
            let raw_evidence = event
                .raw_evidence_reference
                .map(|id| {
                    self.raw_evidence(id)?
                        .ok_or(StorageError::InvalidRawEvidence)
                })
                .transpose()?;
            let size = bytes.len()
                + raw_evidence
                    .as_ref()
                    .map(|raw| serde_json::to_vec(raw).map(|v| v.len()))
                    .transpose()?
                    .unwrap_or(0);
            if batch.len() == 32 || batch_bytes + size > MAX_BATCH_BYTES {
                target.append_records(&batch)?;
                batch.clear();
                batch_bytes = 0;
            }
            batch_bytes += size;
            batch.push(EventRecord {
                event,
                raw_evidence,
            });
        }
        if !batch.is_empty() {
            target.append_records(&batch)?;
        }
        // Preserve all detection annotations exactly, rather than regenerating
        // reviewer state or rule versions from the current binary.
        let mut detections = self
            .connection
            .prepare("SELECT CASE WHEN length(id)<=256 THEN id ELSE NULL END,CASE WHEN length(event_id)<=36 THEN event_id ELSE NULL END,CASE WHEN length(payload)<=4194304 THEN payload ELSE NULL END FROM detections")?;
        for row in detections.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })? {
            let (id, event, payload) = row?;
            let id =
                id.ok_or_else(|| StorageError::Corrupt("oversized detection identity".into()))?;
            let event = event
                .ok_or_else(|| StorageError::Corrupt("oversized detection reference".into()))?;
            let payload = payload
                .ok_or_else(|| StorageError::Corrupt("oversized detection annotation".into()))?;
            target.ensure_append_budget(
                (payload.len() as u64)
                    .saturating_mul(4)
                    .saturating_add(16_384 + 65_536),
            )?;
            target.connection.execute(
                "INSERT OR REPLACE INTO detections(id,event_id,payload) VALUES(?1,?2,?3)",
                params![id, event, payload],
            )?;
        }
        let after = target.verify_integrity()?;
        if before.verified_events != after.verified_events + removed.values().sum::<u64>() {
            return Err(StorageError::Corrupt("noise rewrite count mismatch".into()));
        }
        let report = NoiseCleanupReport {
            policy: "piko.security-noise.v1".into(),
            before,
            after,
            removed,
            chain_rebuilt: true,
        };
        let provenance = serde_json::to_string(&report)?;
        if provenance.len() > MAX_QUERY_BYTES {
            return Err(StorageError::QueryResultTooLarge);
        }
        target.ensure_append_budget(
            (provenance.len() as u64)
                .saturating_mul(4)
                .saturating_add(81_920),
        )?;
        target.connection.execute(
            "INSERT INTO metadata(key,value) VALUES('noise_cleanup_provenance',?1)",
            [provenance],
        )?;
        target.check_budget(target.pending_checkpoint_growth()?)?;
        let busy: u64 =
            target
                .connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        if busy != 0 {
            return Err(StorageError::DiskBudgetExceeded);
        }
        target.check_budget(0)?;
        Ok(report)
    }
}
