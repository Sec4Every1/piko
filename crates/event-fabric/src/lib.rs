#![forbid(unsafe_code)]
mod records;
pub use records::BoundedRecordQueue;

use std::collections::VecDeque;

use piko_event_schema::{SchemaError, SecurityEvent};
use thiserror::Error;

pub const MAX_QUEUE_CAPACITY: usize = 65_536;

/// Single-writer bounded staging queue. Callers must surface overflow in health
/// and persist a loss event once storage is available; errors never imply delivery.
pub struct BoundedEventQueue {
    events: VecDeque<SecurityEvent>,
    capacity: usize,
    dropped_events: u64,
}

impl BoundedEventQueue {
    pub fn new(capacity: usize) -> Result<Self, QueueConfigError> {
        if capacity == 0 || capacity > MAX_QUEUE_CAPACITY {
            return Err(QueueConfigError);
        }
        Ok(Self {
            events: VecDeque::new(),
            capacity,
            dropped_events: 0,
        })
    }

    /// On overflow the rejected event is returned, permitting deliberate retry.
    pub fn try_push(&mut self, event: SecurityEvent) -> Result<(), QueueError> {
        if let Err(error) = event.validate() {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return Err(QueueError {
                event: Box::new(event),
                reason: QueueRejection::InvalidEvent(error),
            });
        }
        if self.events.len() >= self.capacity {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return Err(QueueError {
                event: Box::new(event),
                reason: QueueRejection::Full,
            });
        }
        self.events.push_back(event);
        Ok(())
    }

    /// Draining transfers ownership. A failed durable write must be retried by
    /// the caller without discarding this batch or generating replacement IDs.
    pub fn drain_batch(&mut self, max: usize) -> Vec<SecurityEvent> {
        self.events.drain(..max.min(self.events.len())).collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }
}

#[derive(Debug, Error)]
#[error("queue capacity must be in 1..=65536")]
pub struct QueueConfigError;

#[derive(Debug, Error)]
#[error("telemetry was not accepted: {reason}")]
pub struct QueueError {
    pub event: Box<SecurityEvent>,
    pub reason: QueueRejection,
}

#[derive(Debug, Error)]
pub enum QueueRejection {
    #[error("queue capacity exhausted")]
    Full,
    #[error("invalid event: {0}")]
    InvalidEvent(SchemaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn overflow_is_bounded_observable_and_does_not_replace_old_events() {
        let mut queue = BoundedEventQueue::new(2).expect("queue");
        let host = Uuid::new_v4();
        let runtime = Uuid::new_v4();
        for sequence in 1..=2 {
            queue
                .try_push(SecurityEvent::heartbeat(
                    host, runtime, sequence, 10, sequence,
                ))
                .expect("capacity");
        }
        let rejected = queue
            .try_push(SecurityEvent::heartbeat(host, runtime, 3, 10, 3))
            .expect_err("overflow");
        assert_eq!(rejected.event.sequence, 3);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_events(), 1);
        let batch = queue.drain_batch(1);
        assert_eq!(batch[0].sequence, 1);
        assert_eq!(queue.drain_batch(100)[0].sequence, 2);
        assert!(queue.is_empty());
        assert_eq!(queue.dropped_events(), 1);
    }

    #[test]
    fn zero_or_unbounded_configuration_is_rejected() {
        assert!(BoundedEventQueue::new(0).is_err());
        assert!(BoundedEventQueue::new(MAX_QUEUE_CAPACITY + 1).is_err());
    }

    #[test]
    fn oversized_event_does_not_enter_memory_queue() {
        let mut queue = BoundedEventQueue::new(1).expect("queue");
        let mut event = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 10, 1);
        event.logon_session = Some("x".repeat(piko_event_schema::MAX_EVENT_BYTES));
        let error = queue
            .try_push(event)
            .expect_err("must reject oversized event");
        assert!(matches!(
            error.reason,
            QueueRejection::InvalidEvent(SchemaError::TooLarge)
        ));
        assert!(queue.is_empty());
        assert_eq!(queue.dropped_events(), 1);
    }
}
