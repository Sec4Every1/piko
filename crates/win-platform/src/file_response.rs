//! Narrow Windows boundary: exclusive file handles and user-scoped DPAPI.
use std::{
    fs::{File, OpenOptions},
    io, mem,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree, Security::Cryptography::*, Storage::FileSystem::*,
};

pub const MAX_CONTENT: usize = 16 * 1024 * 1024;

/// Keep this handle alive for the entire response-engine lifetime. The lock
/// file is never truncated or deleted, so concurrent runtimes lock one object.
pub fn lock_vault(directory: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.join("runtime.lock"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "vault lock must be a regular file, not a reparse point",
        ));
    }
    Ok(file)
}

pub struct LockedFile {
    pub file: File,
    pub path: PathBuf,
    pub identity: String,
}

impl LockedFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | DELETE)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let (path, identity) = Self::inspect(&file)?;
        Ok(Self {
            file,
            path,
            identity,
        })
    }
    pub fn create(path: &Path) -> io::Result<Self> {
        Self::create_with_inspection(path, Self::inspect)
    }
    fn create_with_inspection(
        path: &Path,
        inspect: impl FnOnce(&File) -> io::Result<(PathBuf, String)>,
    ) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        match inspect(&file) {
            Ok((path, identity)) => Ok(Self {
                file,
                path,
                identity,
            }),
            Err(error) => {
                // Only this create_new handle owns the new destination. Retain
                // it through cleanup so a path replacement is never deleted.
                if let Err(cleanup) = mark_for_deletion(&file) {
                    return Err(io::Error::other(format!(
                        "new file inspection failed: {error}; removing the incomplete file failed: {cleanup}"
                    )));
                }
                Err(error)
            }
        }
    }
    fn inspect(file: &File) -> io::Result<(PathBuf, String)> {
        let handle = file.as_raw_handle();
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: live owned file handle and correctly sized writable structure.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.nNumberOfLinks != 1
            || info.dwFileAttributes
                & (FILE_ATTRIBUTE_REPARSE_POINT
                    | FILE_ATTRIBUTE_DIRECTORY
                    | FILE_ATTRIBUTE_ENCRYPTED
                    | FILE_ATTRIBUTE_SYSTEM
                    | FILE_ATTRIBUTE_READONLY)
                != 0
        {
            return Err(io::Error::other(
                "unsupported file: links, reparse point, directory, EFS, system or read-only",
            ));
        }
        if file.metadata()?.len() > MAX_CONTENT as u64 {
            return Err(io::Error::other("file exceeds 16 MiB"));
        }
        // u64 allocation provides the alignment required by FILE_STREAM_INFO.
        let mut streams = vec![0u64; 512];
        // SAFETY: aligned buffer is exactly 4096 bytes. Oversized stream lists fail closed.
        if unsafe {
            GetFileInformationByHandleEx(handle, FileStreamInfo, streams.as_mut_ptr().cast(), 4096)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful API populated a FILE_STREAM_INFO in the aligned allocation.
        let first = unsafe { &*streams.as_ptr().cast::<FILE_STREAM_INFO>() };
        let name_offset = mem::offset_of!(FILE_STREAM_INFO, StreamName);
        if first.NextEntryOffset != 0 || first.StreamNameLength != 14 || name_offset + 14 > 4096 {
            return Err(io::Error::other("alternate data streams are not supported"));
        }
        // SAFETY: verified seven UTF-16 code units fit in the buffer above.
        let name = unsafe { std::slice::from_raw_parts(first.StreamName.as_ptr(), 7) };
        if name != "::$DATA".encode_utf16().collect::<Vec<_>>() {
            return Err(io::Error::other("unexpected file stream"));
        }
        let mut path = vec![0u16; 32768];
        // SAFETY: handle is live, output is writable with the advertised capacity.
        let size =
            unsafe { GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), path.len() as u32, 0) }
                as usize;
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        if size >= path.len() {
            return Err(io::Error::other("file path too long"));
        }
        let path = String::from_utf16(&path[..size]).map_err(io::Error::other)?;
        let identity = format!(
            "{:08x}:{:08x}{:08x}:{:08x}{:08x}",
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
            info.ftCreationTime.dwHighDateTime,
            info.ftCreationTime.dwLowDateTime
        );
        Ok((path.into(), identity))
    }
    /// Delete the exact inspected file, never re-resolve a caller supplied path.
    pub fn delete(self) -> io::Result<()> {
        mark_for_deletion(&self.file)?;
        drop(self);
        Ok(())
    }
}

fn mark_for_deletion(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: owned DELETE-capable handle, exact structure/length, synchronous call.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn protect(bytes: &[u8]) -> io::Result<Vec<u8>> {
    crypt(bytes, false)
}
pub fn unprotect(bytes: &[u8]) -> io::Result<Vec<u8>> {
    crypt(bytes, true)
}
fn crypt(bytes: &[u8], decrypt: bool) -> io::Result<Vec<u8>> {
    if bytes.len() > MAX_CONTENT + 64 * 1024 {
        return Err(io::Error::other("DPAPI input limit exceeded"));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input remains alive and unmodified; output is initialized by Windows.
    // No machine-scope flag: only this runtime identity can normally decrypt it.
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = if output.cbData as usize > MAX_CONTENT + 64 * 1024 || output.pbData.is_null() {
        Err(io::Error::other("invalid DPAPI result"))
    } else {
        // SAFETY: successful DPAPI call returns this allocated initialized byte range.
        Ok(unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec())
    };
    // SAFETY: DPAPI output belongs to LocalAlloc; released exactly once.
    unsafe { LocalFree(output.pbData.cast()) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Fixture {
        directory: PathBuf,
        file: PathBuf,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "piko-file-response-test-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&directory)?;
            let file = directory.join("recovered.txt");
            Ok(Self { directory, file })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.file);
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[test]
    fn failed_inspection_removes_only_the_new_destination() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let result = LockedFile::create_with_inspection(&fixture.file, |_| {
            Err(io::Error::other("injected metadata inspection failure"))
        });
        assert!(result.is_err());
        assert!(
            !fixture.file.exists(),
            "failed create must not block recovery"
        );
        // A retry can create and inspect the same path without manual cleanup.
        let file = LockedFile::create(&fixture.file)?;
        file.delete()?;
        assert!(!fixture.file.exists());
        Ok(())
    }

    #[test]
    fn exclusive_create_preserves_a_preexisting_destination() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let original = b"existing user content must survive";
        fs::write(&fixture.file, original)?;
        let result = LockedFile::create_with_inspection(&fixture.file, |_| {
            panic!("an existing destination must fail before inspection")
        });
        match result {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::AlreadyExists),
            Ok(_) => panic!("existing destination unexpectedly opened"),
        }
        assert_eq!(fs::read(&fixture.file)?, original);
        Ok(())
    }
}
