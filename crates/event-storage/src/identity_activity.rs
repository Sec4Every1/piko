use super::*;
use piko_security_core::{authentication_context, AuthenticationContext, AuthenticationKind};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthenticationQuery {
    pub before_position: Option<i64>,
    pub kind: Option<AuthenticationKind>,
    pub limit: usize,
}
impl Default for AuthenticationQuery {
    fn default() -> Self {
        Self {
            before_position: None,
            kind: None,
            limit: 5,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationRecord {
    pub position: i64,
    pub kind: AuthenticationKind,
    pub event: SecurityEvent,
    pub context: AuthenticationContext,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationPage {
    pub records: Vec<AuthenticationRecord>,
    pub next_before: Option<i64>,
}
impl SqliteEventStore {
    pub fn authentication_activity(
        &self,
        filter: &AuthenticationQuery,
    ) -> Result<AuthenticationPage, StorageError> {
        if !(1..=20).contains(&filter.limit) || filter.before_position.is_some_and(|p| p <= 0) {
            return Err(StorageError::InvalidQuery);
        }
        let _snapshot = if self.connection.is_autocommit() {
            Some(self.connection.unchecked_transaction()?)
        } else {
            None
        };
        let mut query=self.connection.prepare("SELECT position,payload FROM events WHERE sensor_id='windows.event_log.Security' AND event_type IN ('windows.event_log.4624','windows.event_log.4625','windows.event_log.4648','windows.event_log.4672') AND (?1 IS NULL OR position<?1) AND (?2 IS NULL OR event_type=?2) ORDER BY position DESC LIMIT ?3")?;
        let mut rows = query.query(params![
            filter.before_position,
            filter.kind.map(|kind| kind.event_type()),
            (filter.limit + 1) as i64
        ])?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let mut next_before = None;
        while let Some(row) = rows.next()? {
            if records.len() == filter.limit {
                next_before = records.last().map(|r: &AuthenticationRecord| r.position);
                break;
            }
            let position = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            bytes = bytes.saturating_add(payload.len());
            let event = SecurityEvent::decode(&payload)?;
            let raw = event
                .raw_evidence_reference
                .map(|id| self.raw_evidence(id))
                .transpose()?
                .flatten();
            bytes = bytes.saturating_add(raw.as_ref().map_or(0, |r| r.bytes.len()));
            if bytes > MAX_QUERY_BYTES {
                return Err(StorageError::QueryResultTooLarge);
            }
            let kind = AuthenticationKind::from_event_type(&event.event_type)
                .ok_or(StorageError::InvalidQuery)?;
            let context = authentication_context(&event, raw.as_ref());
            records.push(AuthenticationRecord {
                position,
                kind,
                event,
                context,
            });
        }
        Ok(AuthenticationPage {
            records,
            next_before,
        })
    }
}
