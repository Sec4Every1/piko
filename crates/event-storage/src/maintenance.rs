use crate::{SqliteEventStore, StorageError};
use serde::{Deserialize, Serialize};

/// Cached outcome of one bounded archive pass, not a physical disk-space claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMaintenanceStatus {
    pub enabled: bool,
    pub state: String,
    pub sampled_at_unix_ms: Option<i64>,
    pub scanned: u64,
    pub changed: u64,
    pub logical_bytes_saved: u64,
    pub cycle_complete: bool,
    pub detail: Option<String>,
}

impl Default for ArchiveMaintenanceStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            state: "waiting".into(),
            sampled_at_unix_ms: None,
            scanned: 0,
            changed: 0,
            logical_bytes_saved: 0,
            cycle_complete: false,
            detail: None,
        }
    }
}

impl SqliteEventStore {
    pub fn maintain_archive_batch(
        &mut self,
        after: i64,
    ) -> Result<(i64, u64, u64, u64), StorageError> {
        // open() already validated this writer. Avoid repeating an archive-wide
        // orphan-envelope scan for each small pass; still check owner metadata.
        if self.evidence_protection_mode()?.is_some() && !self.config.protect_new_evidence {
            return Err(StorageError::ProtectionPolicy(
                "archive maintenance requires the configured protection writer".into(),
            ));
        }
        self.validate_evidence_protection(false)?;
        self.compress_existing_evidence(after)
    }
}
