use piko_event_schema::EventRecord;
use std::collections::VecDeque;

pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
const QUEUE_BYTES: usize = 16 * 1024 * 1024;
const BATCH_BYTES: usize = 2 * 1024 * 1024;

/// Bounds both count and serialized bytes, including the original evidence.
pub struct BoundedRecordQueue {
    records: VecDeque<(EventRecord, usize)>,
    capacity: usize,
    bytes: usize,
    dropped: u64,
}
impl BoundedRecordQueue {
    pub fn new(capacity: usize) -> Result<Self, super::QueueConfigError> {
        if capacity == 0 || capacity > super::MAX_QUEUE_CAPACITY {
            return Err(super::QueueConfigError);
        }
        Ok(Self {
            records: VecDeque::new(),
            capacity,
            bytes: 0,
            dropped: 0,
        })
    }
    /// Reserve the largest permitted record before reading a live source.
    pub fn has_room(&self) -> bool {
        self.len() < self.capacity && self.bytes + MAX_RECORD_BYTES <= QUEUE_BYTES
    }
    pub fn try_push(&mut self, record: EventRecord) -> Result<(), String> {
        let result = (|| {
            record.event.validate().map_err(|e| e.to_string())?;
            if record
                .raw_evidence
                .as_ref()
                .is_some_and(|raw| raw.bytes.len() > piko_event_schema::MAX_RAW_EVIDENCE_BYTES)
            {
                return Err("raw evidence limit".into());
            }
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| e.to_string())?
                .len();
            if bytes > MAX_RECORD_BYTES
                || self.bytes + bytes > QUEUE_BYTES
                || self.len() == self.capacity
            {
                return Err("record queue limit".into());
            }
            self.bytes += bytes;
            self.records.push_back((record, bytes));
            Ok(())
        })();
        if result.is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
        result
    }
    pub fn drain_batch(&mut self, max: usize) -> Vec<EventRecord> {
        let mut result = Vec::new();
        let mut bytes = 0;
        while result.len() < max
            && self
                .records
                .front()
                .is_some_and(|(_, size)| bytes + size <= BATCH_BYTES)
        {
            if let Some((record, size)) = self.records.pop_front() {
                self.bytes -= size;
                bytes += size;
                result.push(record);
            }
        }
        result
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn dropped_events(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use piko_event_schema::{RawEvidence, SecurityEvent};
    use uuid::Uuid;
    #[test]
    fn original_evidence_survives_bounded_batches() -> Result<(), Box<dyn std::error::Error>> {
        let mut queue = BoundedRecordQueue::new(2)?;
        let mut event = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 1, 1);
        let evidence_id = Uuid::new_v4();
        event.raw_evidence_reference = Some(evidence_id);
        let record = EventRecord {
            event,
            raw_evidence: Some(RawEvidence {
                evidence_id,
                source: "test".into(),
                content_type: "application/xml".into(),
                observed_at_unix_ms: 1,
                bytes: b"<Event/>".to_vec(),
            }),
        };
        queue.try_push(record.clone())?;
        queue.try_push(record.clone())?;
        assert!(!queue.has_room());
        assert!(queue.try_push(record.clone()).is_err());
        assert_eq!(queue.dropped_events(), 1);
        assert_eq!(queue.drain_batch(1), vec![record]);
        assert!(queue.has_room());
        Ok(())
    }
}
