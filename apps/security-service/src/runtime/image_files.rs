//! Read-only file snapshots held only for one bounded collection batch.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    time::Instant,
};
#[derive(Clone, Debug, Serialize, PartialEq, Eq, Hash)]
pub struct FileFingerprint {
    pub path: String,
    pub sha256: String,
}
pub struct HeldImage {
    pub fingerprint: FileFingerprint,
    pub file: File,
    _parents: Vec<File>,
}
pub fn inspect(value: &str, deadline: Instant) -> io::Result<HeldImage> {
    let path = piko_win_platform::network_elevation::local_image_path(value)?;
    let parents = piko_win_platform::network_elevation::lock_path_parents(&path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000 | 0x00100000)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x1400 != 0
        || !(64..=64 * 1024 * 1024).contains(&metadata.len())
    {
        return Err(io::Error::other(
            "Image file not eligible for a bounded snapshot",
        ));
    }
    let canonical = piko_win_platform::network_elevation::final_file_path(&file)?;
    if canonical.to_string_lossy().to_lowercase() != path.to_string_lossy().to_lowercase() {
        return Err(io::Error::other("Image path redirected"));
    }
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    let offset = u32::from_le_bytes(header[60..64].try_into().map_err(io::Error::other)?) as u64;
    if &header[..2] != b"MZ" || offset < 64 || offset > metadata.len() - 4 {
        return Err(io::Error::other("Invalid PE image"));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut pe = [0u8; 4];
    file.read_exact(&mut pe)?;
    if pe != *b"PE\0\0" {
        return Err(io::Error::other("Invalid PE signature"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::other("Image fingerprint deadline"));
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > metadata.len() {
            return Err(io::Error::other("Image size changed"));
        }
        hash.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err(io::Error::other("Incomplete image snapshot"));
    }
    Ok(HeldImage {
        fingerprint: FileFingerprint {
            path: canonical.to_string_lossy().into_owned(),
            sha256: format!("{:x}", hash.finalize()),
        },
        file,
        _parents: parents,
    })
}
