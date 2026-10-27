//! Pending-state checks against synthetic directories, without starting runtime.
use super::{require_no_pending_archive_verification, Config};
use std::{error::Error, fs, path::PathBuf};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("piko-key-guard-test-{}", Uuid::new_v4()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pending_verification_or_recovery_blocks_collection_and_preserves_marker(
) -> Result<(), Box<dyn Error>> {
    for name in [
        "archive-verification.pending",
        "evidence-key.recovery.pending",
    ] {
        let directory = Directory::new()?;
        let config = Config {
            data_dir: directory.0.clone(),
            ..Default::default()
        };
        assert!(!config.protect_raw_evidence && !config.recoverable_raw_evidence);
        assert!(require_no_pending_archive_verification(&config).is_ok());
        let marker = directory.0.join(name);
        fs::write(&marker, b"synthetic interrupted operation")?;
        assert!(require_no_pending_archive_verification(&config).is_err());
        assert_eq!(fs::read(marker)?, b"synthetic interrupted operation");
        assert!(!directory.0.join("events.db").exists());
    }
    Ok(())
}

#[test]
fn pending_activation_allows_only_forward_flags_and_never_removes_the_journal(
) -> Result<(), Box<dyn Error>> {
    let directory = Directory::new()?;
    let marker = directory.0.join("evidence-protection-activation.pending");
    fs::write(&marker, b"synthetic activation journal")?;
    for (protect_raw_evidence, recoverable_raw_evidence, allowed) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let config = Config {
            data_dir: directory.0.clone(),
            protect_raw_evidence,
            recoverable_raw_evidence,
            ..Default::default()
        };
        assert_eq!(
            require_no_pending_archive_verification(&config).is_ok(),
            allowed
        );
        assert_eq!(fs::read(&marker)?, b"synthetic activation journal");
    }
    Ok(())
}
