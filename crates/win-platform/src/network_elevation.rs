//! Narrow UAC launch boundary for the adjacent, purpose-built network helper.
use std::{
    fs::{File, OpenOptions},
    io,
    marker::PhantomData,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    ptr,
    rc::Rc,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::FileSystem::{GetDriveTypeW, GetFinalPathNameByHandleW, QueryDosDeviceW},
    System::{
        Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE},
        SystemInformation::GetWindowsDirectoryW,
        Threading::{
            CreateMutexW, GetExitCodeProcess, GetProcessTimes, OpenProcess, ReleaseMutex,
            WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    },
    UI::{
        Shell::{
            ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

const NETWORK_OPERATION_MUTEX: &str = r"Global\piko.network-operation.v1";

/// PID plus creation time binds a plan to one desktop instance despite PID reuse.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlanOrigin {
    pub pid: u32,
    pub creation_filetime: String,
}
impl NetworkPlanOrigin {
    pub fn valid(&self) -> bool {
        self.pid >= 8
            && self.creation_filetime.len() <= 20
            && self
                .creation_filetime
                .parse::<u64>()
                .is_ok_and(|v| v != 0 && v.to_string() == self.creation_filetime)
    }
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: uniquely owned real kernel handle.
        unsafe { CloseHandle(self.0) };
    }
}

fn process_creation(handle: &OwnedHandle) -> io::Result<String> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: live query handle and exact writable FILETIME buffers.
    if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let value = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if value == 0 {
        return Err(io::Error::other(
            "Desktop process creation identity unavailable",
        ));
    }
    Ok(value.to_string())
}

fn open_origin(origin: &NetworkPlanOrigin) -> io::Result<OwnedHandle> {
    if !origin.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid desktop process identity",
        ));
    }
    // SAFETY: minimal read/synchronize rights, scalar PID, no handle inheritance.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            origin.pid,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let handle = OwnedHandle(raw);
    if process_creation(&handle)? != origin.creation_filetime {
        return Err(io::Error::other(
            "Original desktop process identity changed",
        ));
    }
    ensure_process_alive(&handle)?;
    Ok(handle)
}

fn ensure_process_alive(handle: &OwnedHandle) -> io::Result<()> {
    // SAFETY: owned synchronization handle; nonblocking liveness check.
    match unsafe { WaitForSingleObject(handle.0, 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(io::Error::other(
            "Original desktop has closed; prepare the action again",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn current_network_plan_origin() -> io::Result<NetworkPlanOrigin> {
    let pid = std::process::id();
    // SAFETY: current PID, minimal query rights, no inheritance.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(NetworkPlanOrigin {
        pid,
        creation_filetime: process_creation(&OwnedHandle(raw))?,
    })
}

struct OperationMutex {
    handle: OwnedHandle,
    // A Windows mutex must be released by the thread that acquired it.
    _thread_bound: PhantomData<Rc<()>>,
}
impl OperationMutex {
    fn acquire(name: &str) -> io::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: terminated name; default DACL. Access errors fail closed.
        let raw = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = OwnedHandle(raw);
        // SAFETY: owned mutex handle, nonblocking acquisition (never queue stale actions).
        match unsafe { WaitForSingleObject(handle.0, 0) } {
            WAIT_OBJECT_0 => Ok(Self {
                handle,
                _thread_bound: PhantomData,
            }),
            WAIT_ABANDONED => {
                let _guard = Self {
                    handle,
                    _thread_bound: PhantomData,
                };
                Err(io::Error::other(
                    "Previous network action ended unexpectedly; refresh rules and prepare again",
                ))
            }
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Another network action is still running; wait and refresh the rules",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
impl Drop for OperationMutex {
    fn drop(&mut self) {
        // SAFETY: this thread acquired the mutex; handle stays live through release.
        unsafe { ReleaseMutex(self.handle.0) };
    }
}

/// Held by the helper through mutation and final audit, including after desktop exit.
/// A restarted desktop's helper cannot overtake an action already in progress.
pub struct NetworkOperationGuard {
    _mutex: OperationMutex,
    origin: OwnedHandle,
}
impl NetworkOperationGuard {
    pub fn ensure_origin_alive(&self) -> io::Result<()> {
        ensure_process_alive(&self.origin)
    }
}
pub fn begin_network_operation(origin: &NetworkPlanOrigin) -> io::Result<NetworkOperationGuard> {
    begin_named_network_operation(origin, NETWORK_OPERATION_MUTEX)
}
fn begin_named_network_operation(
    origin: &NetworkPlanOrigin,
    name: &str,
) -> io::Result<NetworkOperationGuard> {
    let mutex = OperationMutex::acquire(name)?;
    let origin = open_origin(origin)?;
    Ok(NetworkOperationGuard {
        _mutex: mutex,
        origin,
    })
}

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
/// Call on a blocking worker. Retain ownership until the helper has terminated;
/// returning a timeout would allow a later action to overtake a still-running mutation.
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
    // SAFETY: valid owned process handle. This blocking worker awaits terminal completion.
    match unsafe { WaitForSingleObject(process.0, INFINITE) } {
        WAIT_OBJECT_0 => {}
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

    struct ChildFixture(std::process::Child);
    impl Drop for ChildFixture {
        fn drop(&mut self) {
            // Only the child test harness created by this fixture is terminated.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child_fixture(test: &str) -> io::Result<std::process::Command> {
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .args(["--exact", test, "--ignored", "--nocapture"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        Ok(command)
    }
    fn child_origin(child: &std::process::Child) -> io::Result<NetworkPlanOrigin> {
        // SAFETY: PID of our child, query rights only, no inheritance.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, child.id()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(NetworkPlanOrigin {
            pid: child.id(),
            creation_filetime: process_creation(&OwnedHandle(raw))?,
        })
    }

    #[test]
    fn origin_identity_rejects_pid_reuse_and_dead_desktop() -> io::Result<()> {
        let origin = current_network_plan_origin()?;
        let live = open_origin(&origin)?;
        ensure_process_alive(&live)?;
        let mut reused = origin.clone();
        reused.creation_filetime = "1".into();
        assert!(open_origin(&reused).is_err());
        for value in ["", "0", "01", "-1", "18446744073709551616"] {
            reused.creation_filetime = value.into();
            assert!(!reused.valid());
        }
        let mut child = ChildFixture(
            child_fixture("network_elevation::tests::origin_lifetime_child")?.spawn()?,
        );
        let child_origin = child_origin(&child.0)?;
        let name = format!(r"Local\piko-network-origin-test-{}", uuid::Uuid::new_v4());
        let operation = begin_named_network_operation(&child_origin, &name)?;
        operation.ensure_origin_alive()?;
        // EOF makes the benign child exit normally, simulating a closed desktop.
        drop(child.0.stdin.take());
        assert!(child.0.wait()?.success());
        assert!(operation.ensure_origin_alive().is_err());
        drop(operation);
        assert!(begin_named_network_operation(&child_origin, &name).is_err());
        // Failure releases the mutex so a new desktop instance can act.
        let _new_operation = begin_named_network_operation(&origin, &name)?;
        Ok(())
    }

    #[test]
    #[ignore = "benign subprocess fixture; run only by origin_identity_rejects_pid_reuse_and_dead_desktop"]
    fn origin_lifetime_child() -> io::Result<()> {
        let mut input = String::new();
        io::Read::read_to_string(&mut io::stdin(), &mut input)?;
        Ok(())
    }

    fn running_mutex_child(
        name: &str,
    ) -> io::Result<(ChildFixture, io::BufReader<std::process::ChildStdout>)> {
        use io::BufRead;
        let mut command = child_fixture("network_elevation::tests::mutex_lifetime_child")?;
        command.env("PIKO_NETWORK_MUTEX_FIXTURE", name);
        let mut child = ChildFixture(command.spawn()?);
        let stdout = child
            .0
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("Missing fixture stdout"))?;
        let mut output = io::BufReader::new(stdout);
        let mut ready = false;
        loop {
            let mut line = String::new();
            if output.read_line(&mut line)? == 0 {
                break;
            }
            if line.contains("piko-mutex-ready") {
                ready = true;
                break;
            }
        }
        assert!(ready, "Mutex fixture did not start");
        Ok((child, output))
    }

    #[test]
    fn operation_mutex_excludes_other_processes_and_releases_on_exit() -> io::Result<()> {
        let name = format!(r"Local\piko-network-mutex-test-{}", uuid::Uuid::new_v4());
        let (mut child, _output) = running_mutex_child(&name)?;
        assert!(
            matches!(OperationMutex::acquire(&name), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        drop(child.0.stdin.take());
        assert!(child.0.wait()?.success());
        let _operation = OperationMutex::acquire(&name)?;
        Ok(())
    }

    #[test]
    fn abandoned_operation_requires_refresh_then_allows_fresh_action() -> io::Result<()> {
        let name = format!(
            r"Local\piko-network-abandoned-test-{}",
            uuid::Uuid::new_v4()
        );
        let (mut child, _output) = running_mutex_child(&name)?;
        let encoded: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: terminated unique fixture name. Retain the object without owning
        // the mutex, so killing our child fixture exposes WAIT_ABANDONED.
        let raw = unsafe { CreateMutexW(ptr::null(), 0, encoded.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _retained = OwnedHandle(raw);
        child.0.kill()?;
        child.0.wait()?;
        assert!(matches!(OperationMutex::acquire(&name), Err(error)
            if error.to_string().contains("ended unexpectedly")));
        // The failed acquisition released its abandoned ownership before returning.
        let _fresh = OperationMutex::acquire(&name)?;
        Ok(())
    }

    #[test]
    #[ignore = "benign subprocess fixture; run only by operation_mutex tests"]
    fn mutex_lifetime_child() -> io::Result<()> {
        let name = std::env::var("PIKO_NETWORK_MUTEX_FIXTURE").map_err(io::Error::other)?;
        let _operation = OperationMutex::acquire(&name)?;
        println!("piko-mutex-ready");
        let mut input = String::new();
        io::Read::read_to_string(&mut io::stdin(), &mut input)?;
        Ok(())
    }

    #[test]
    fn rejects_arbitrary_helper_or_arguments_without_uac() {
        assert!(launch_network_helper(Path::new(r"C:\Windows\cmd.exe"), "aa").is_err());
        assert!(
            launch_network_helper(Path::new(r"C:\piko-network-helper.exe"), "aa & calc").is_err()
        );
        assert!(windows_directory().is_ok_and(|p| p.is_absolute()));
    }
}
