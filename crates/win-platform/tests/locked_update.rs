#![cfg(windows)]
//! Temporary plain files only; no installed files, DPAPI state or ACL changes.
use piko_win_platform::file_response::LockedFile;
use std::{
    error::Error,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
use uuid::Uuid;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn writable_inspection_never_creates_or_truncates_and_releases_ownership(
) -> Result<(), Box<dyn Error>> {
    let directory =
        Directory(std::env::temp_dir().join(format!("piko-update-lock-{}", Uuid::new_v4())));
    fs::create_dir(&directory.0)?;
    let missing = directory.0.join("missing.bin");
    assert!(LockedFile::open_for_update(&missing).is_err());
    assert!(!missing.exists());

    let path = directory.0.join("existing.bin");
    fs::write(&path, b"original")?;
    let mut locked = LockedFile::open_for_update(&path)?;
    assert_eq!(locked.file.metadata()?.len(), 8);
    locked.file.seek(SeekFrom::Start(0))?;
    let mut original = Vec::new();
    locked.file.read_to_end(&mut original)?;
    assert_eq!(original, b"original");
    assert!(LockedFile::open_for_update(&path).is_err());
    assert!(fs::rename(&path, directory.0.join("moved.bin")).is_err());
    locked.file.seek(SeekFrom::Start(0))?;
    locked.file.write_all(b"updated!")?;
    locked.file.sync_all()?;
    drop(locked);
    assert_eq!(fs::read(&path)?, b"updated!");
    let reopened = LockedFile::open_for_update(&path)?;
    drop(reopened);
    Ok(())
}
