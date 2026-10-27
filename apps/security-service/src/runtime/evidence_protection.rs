use piko_event_storage::EvidenceProtection;
use std::io;

/// Uses the existing Windows user-scoped DPAPI boundary. Protected evidence
/// requires the same runtime account and its DPAPI keys for later recovery;
/// administrator elevation alone does not provide another account's keys.
#[derive(Debug)]
pub(super) struct WindowsEvidenceProtection;

impl EvidenceProtection for WindowsEvidenceProtection {
    fn protect(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        piko_win_platform::file_response::protect(bytes)
    }

    fn unprotect(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        piko_win_platform::file_response::unprotect(bytes)
    }
}

// Recoverable keys use DPAPI only for the local key copy. This does not change
// the active evidence provider or make legacy DPAPI blobs portable.
impl piko_crypto::KeyProtector for WindowsEvidenceProtection {
    fn protect_key(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        piko_win_platform::file_response::protect(bytes)
    }
    fn unprotect_key(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        piko_win_platform::file_response::unprotect(bytes)
    }
}

pub(super) struct RecoverableEvidenceProtection {
    key: io::Result<super::key_bundle::LoadedKey>,
}
impl std::fmt::Debug for RecoverableEvidenceProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverableEvidenceProtection([REDACTED])")
    }
}
impl RecoverableEvidenceProtection {
    pub(super) fn for_read_only_recovery(
        archive_id: uuid::Uuid,
        key: std::sync::Arc<piko_crypto::EvidenceKey>,
    ) -> Self {
        Self {
            key: Ok(super::key_bundle::LoadedKey {
                archive_id,
                recipient: key.recipient(),
                key,
                backup_confirmed: false,
            }),
        }
    }
    pub(super) fn load(directory: &std::path::Path) -> Self {
        Self {
            key: super::key_bundle::load(directory),
        }
    }
    fn loaded(&self) -> io::Result<&super::key_bundle::LoadedKey> {
        self.key.as_ref().map_err(|_| {
            io::Error::other("recoverable evidence key is unavailable; no fallback is permitted")
        })
    }
}
impl EvidenceProtection for RecoverableEvidenceProtection {
    fn validate_new_writes(&self) -> io::Result<()> {
        if !self.loaded()?.backup_confirmed {
            return Err(io::Error::other(
                "recovery-code backup confirmation required",
            ));
        }
        Ok(())
    }
    fn scheme(&self) -> &'static str {
        "age-x25519-v1"
    }
    fn key_identity(&self) -> Option<String> {
        self.key
            .as_ref()
            .ok()
            .map(|loaded| format!("{}:{}", loaded.archive_id, loaded.recipient))
    }
    fn protect(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let loaded = self.loaded()?;
        if !loaded.backup_confirmed {
            return Err(io::Error::other(
                "recovery-code backup must be confirmed before protected writes",
            ));
        }
        loaded.key.encrypt(loaded.archive_id, bytes)
    }
    fn unprotect(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let loaded = self.loaded()?;
        Ok(loaded.key.decrypt(loaded.archive_id, bytes)?.to_vec())
    }
}
