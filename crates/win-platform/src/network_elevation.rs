//! Narrow UAC launch boundary for the adjacent, purpose-built network helper.
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::FileSystem::{GetDriveTypeW, GetFinalPathNameByHandleW, QueryDosDeviceW},
    System::{
        Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE},
        SystemInformation::GetWindowsDirectoryW,
        Threading::{GetExitCodeProcess, WaitForSingleObject},
    },
    UI::{
        Shell::{
            ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

/// Map only fixed local DOS drives; never resolve MUP/network/device namespaces
/// or infer a disk path merely from a familiar filename.
pub fn local_image_path(value: &str) -> io::Result<PathBuf> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(io::Error::other("Invalid image path"));
    }
    let bytes = value.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\" {
        return Ok(PathBuf::from(value));
    }
    if !value.starts_with("\\Device\\HarddiskVolume") {
        return Err(io::Error::other("Unsupported image namespace"));
    }
    for letter in b'A'..=b'Z' {
        let name = [u16::from(letter), u16::from(b':'), 0];
        let mut buffer = [0u16; 4096];
        // SAFETY: terminated drive name and bounded writable target buffer.
        let count =
            unsafe { QueryDosDeviceW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) }
                as usize;
        if count == 0 || count > buffer.len() {
            continue;
        }
        let Some(end) = buffer[..count].iter().position(|v| *v == 0) else {
            continue;
        };
        let Ok(target) = String::from_utf16(&buffer[..end]) else {
            continue;
        };
        if let Some(rest) = value.strip_prefix(&target).filter(|v| v.starts_with('\\')) {
            return Ok(PathBuf::from(format!("{}:{rest}", char::from(letter))));
        }
    }
    Err(io::Error::other("No unambiguous local drive mapping"))
}

/// Hold every directory against writes and renames, from drive root to immediate parent.
/// This prevents path redirection while a path-scoped Firewall change is prepared/applied.
pub fn lock_path_parents(path: &Path) -> io::Result<Vec<File>> {
    let raw = path
        .to_str()
        .ok_or_else(|| io::Error::other("Non-Unicode path"))?;
    let bytes = raw.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
        return Err(io::Error::other("Expected a local absolute DOS path"));
    }
    let root: Vec<u16> = raw[..3].encode_utf16().chain(Some(0)).collect();
    // SAFETY: terminated root path; read-only classification of the volume.
    if !matches!(unsafe { GetDriveTypeW(root.as_ptr()) }, 2 | 3 | 6) {
        return Err(io::Error::other(
            "The executable must reside on a local disk",
        ));
    }
    let mut parents = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing parent"))?
        .ancestors()
        .collect::<Vec<_>>();
    parents.reverse();
    let mut handles = Vec::with_capacity(parents.len());
    for parent in parents {
        let handle = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x02000000 | 0x00200000)
            .open(parent)?;
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other(
                "Parent is not a regular directory or is a reparse point",
            ));
        }
        handles.push(handle);
    }
    Ok(handles)
}

pub fn final_file_path(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0_u16; 32768];
    // SAFETY: borrowed live file handle and bounded writable output buffer; normalized DOS path.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if count == 0 || count >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let value = String::from_utf16(&buffer[..count]).map_err(io::Error::other)?;
    Ok(PathBuf::from(value.strip_prefix(r"\\?\").unwrap_or(&value)))
}

pub fn windows_directory() -> io::Result<PathBuf> {
    let mut buffer = [0_u16; 32768];
    // SAFETY: writable bounded UTF-16 output buffer; kernel writes at most its capacity.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(
        String::from_utf16(&buffer[..length]).map_err(io::Error::other)?,
    ))
}

/// No shell or script: one validated hex argument, fixed executable basename and explicit runas.
/// Call on a blocking worker. Timeout does not terminate the elevated process; caller must reread rules.
pub fn launch_network_helper(helper: &Path, payload: &str) -> io::Result<u32> {
    if helper.file_name().and_then(|n| n.to_str()) != Some("piko-network-helper.exe")
        || !helper.is_absolute()
        || payload.is_empty()
        || payload.len() > 24576
        || !payload.len().is_multiple_of(2)
        || !payload.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid network helper launch.",
        ));
    }
    let _parents = lock_path_parents(helper)?;
    // Keep the exact helper from being rewritten/deleted between validation and process completion.
    let locked = OpenOptions::new().read(true).share_mode(1).open(helper)?;
    if !locked.metadata()?.is_file() || locked.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("Network helper is not a regular file."));
    }
    if final_file_path(&locked)?.to_string_lossy().to_lowercase()
        != helper.to_string_lossy().to_lowercase()
    {
        return Err(io::Error::other(
            "Network helper path does not match the opened file",
        ));
    }
    let path = helper
        .to_str()
        .filter(|s| !s.contains('\0'))
        .ok_or_else(|| io::Error::other("Invalid helper path."))?;
    let file: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let parameters: Vec<u16> = payload.encode_utf16().chain(Some(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    // SAFETY: no reserved input, dedicated worker uses STA until the matching guard drops.
    let status = unsafe {
        CoInitializeEx(
            ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "UAC COM initialization failed: {status:#x}"
        )));
    }
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            /* SAFETY: balances this thread's successful initialization. */
            unsafe { CoUninitialize() };
        }
    }
    let _com = ComGuard;
    // SAFETY: zero initializes optional fields; required fields and size are set before use.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: all strings live for the synchronous launch; no shell command is parsed.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.hProcess.is_null() {
        return Err(io::Error::other(
            "Windows did not return a helper process handle. Refresh firewall rules.",
        ));
    }
    struct Process(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Process {
        fn drop(&mut self) {
            /* SAFETY: unique process handle returned by ShellExecuteExW. */
            unsafe { CloseHandle(self.0) };
        }
    }
    let process = Process(info.hProcess);
    // SAFETY: valid owned process handle; bounded wait after UAC authorization returns.
    match unsafe { WaitForSingleObject(process.0, 60_000) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Modifica ancora in corso: aggiorna le regole prima di riprovare.",
            ))
        }
        _ => return Err(io::Error::last_os_error()),
    }
    let mut code = 0;
    // SAFETY: live completed process handle and valid output pointer.
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_arbitrary_helper_or_arguments_without_uac() {
        assert!(launch_network_helper(Path::new(r"C:\Windows\cmd.exe"), "aa").is_err());
        assert!(
            launch_network_helper(Path::new(r"C:\piko-network-helper.exe"), "aa & calc").is_err()
        );
        assert!(windows_directory().is_ok_and(|p| p.is_absolute()));
    }
}
