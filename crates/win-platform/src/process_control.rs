//! Stop a single, explicitly selected process owned by the same user/session.
use std::{io, path::Path};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        GetProcessTimes, IsProcessCritical, OpenProcess, QueryFullProcessImageNameW,
        TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    },
};
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessTarget {
    pub pid: u32,
    pub creation_filetime: String,
    pub executable: String,
    pub name: String,
    pub sid: String,
    pub session_id: u32,
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: uniquely owned real OpenProcess handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn open(pid: u32, terminate: bool) -> io::Result<Handle> {
    if pid < 8 || pid == std::process::id() {
        return Err(denied("System and piko processes are excluded"));
    }
    // SAFETY: scalar PID, minimal requested rights, no inheritance, owned output.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_SYNCHRONIZE
                | if terminate { PROCESS_TERMINATE } else { 0 },
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(handle))
}
fn inspect(handle: &Handle, pid: u32) -> io::Result<ProcessTarget> {
    if crate::current_process_elevated()? {
        return Err(denied("Use the normal user interface"));
    }
    let caller = crate::current_identity()?;
    let identity = crate::identity_of_process(handle.0)?;
    if identity != caller {
        return Err(denied(
            "Only processes of this user and Windows session can be stopped",
        ));
    }
    let mut critical = 0;
    // SAFETY: live query handle and writable BOOL; any failed query denies operation.
    if unsafe { IsProcessCritical(handle.0, &mut critical) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if critical != 0 {
        return Err(denied("Critical process excluded"));
    }
    // SAFETY: live synchronize handle, no wait. A signaled process has already ended.
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(io::Error::other("Process is no longer running"));
    }
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: live query handle and exact FILETIME buffers.
    if unsafe { GetProcessTimes(handle.0, &mut created, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let time = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if time == 0 {
        return Err(io::Error::other("Process creation identity unavailable"));
    }
    let mut buffer = [0u16; 4096];
    let mut units = buffer.len() as u32;
    // SAFETY: live query handle, bounded writable UTF-16 buffer and in/out length.
    if unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut units) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if units == 0 || units as usize >= buffer.len() {
        return Err(io::Error::other("Process path exceeds bound"));
    }
    let executable = String::from_utf16(&buffer[..units as usize]).map_err(io::Error::other)?;
    let path = std::fs::canonicalize(&executable)?;
    let windows = std::fs::canonicalize(crate::network_elevation::windows_directory()?)?;
    let lower = path.to_string_lossy().to_lowercase();
    let protected = windows.to_string_lossy().to_lowercase();
    let own = std::env::current_exe()?;
    let own_root = std::fs::canonicalize(
        own.parent()
            .ok_or_else(|| io::Error::other("Missing application directory"))?,
    )?;
    if Path::new(&lower).starts_with(&protected)
        || Path::new(&lower).starts_with(own_root.to_string_lossy().to_lowercase())
    {
        return Err(denied(
            "Windows and piko installation processes are excluded",
        ));
    }
    let name = Path::new(&executable)
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| io::Error::other("Process executable name unavailable"))?
        .to_string();
    if [
        "piko.exe",
        "piko-service.exe",
        "piko-desktop.exe",
        "piko-network-helper.exe",
    ]
    .contains(&name.to_ascii_lowercase().as_str())
    {
        return Err(denied("piko processes are excluded"));
    }
    if executable.chars().any(char::is_control) || executable.len() > 8192 {
        return Err(io::Error::other("Invalid process path"));
    }
    Ok(ProcessTarget {
        pid,
        creation_filetime: time.to_string(),
        executable,
        name,
        sid: identity.sid,
        session_id: identity.session_id,
    })
}
pub fn preview(pid: u32, creation_filetime: &str) -> io::Result<ProcessTarget> {
    let handle = open(pid, false)?;
    let target = inspect(&handle, pid)?;
    if target.creation_filetime != creation_filetime {
        return Err(denied("Process instance changed; refresh observations"));
    }
    Ok(target)
}
pub fn terminate(target: &ProcessTarget) -> io::Result<bool> {
    let handle = open(target.pid, true)?;
    if inspect(&handle, target.pid)? != *target {
        return Err(denied("Process identity changed after preview"));
    }
    let mut critical = 0;
    // SAFETY: same held process handle, recheck critical state immediately before effect.
    if unsafe { IsProcessCritical(handle.0, &mut critical) } == 0 || critical != 0 {
        return Err(denied(
            "Critical process query failed or process is critical",
        ));
    }
    // SAFETY: exact held handle bound to full preview identity; caller explicitly confirmed.
    if unsafe { TerminateProcess(handle.0, 0x50494B4F) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same synchronize handle; bounded wait establishes exit, not just submission.
    match unsafe { WaitForSingleObject(handle.0, 2000) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_and_system_processes_are_never_targets() {
        assert!(preview(std::process::id(), "1").is_err());
        assert!(preview(0, "1").is_err());
        assert!(preview(4, "1").is_err());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    fn owned_sleep_fixture() {
        if std::env::var("PIKO_PROCESS_TEST_FIXTURE").ok().as_deref() == Some("1") {
            std::thread::sleep(std::time::Duration::from_secs(15));
        }
    }
    #[test]
    fn exact_owned_instance_is_stopped_or_elevated_caller_is_denied() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("piko-process-test-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let path = dir.join("benign-fixture.exe");
        std::fs::copy(std::env::current_exe()?, &path)?;
        let mut child = Child(
            std::process::Command::new(&path)
                .args([
                    "--exact",
                    "process_control::live_tests::owned_sleep_fixture",
                    "--nocapture",
                ])
                .env("PIKO_PROCESS_TEST_FIXTURE", "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?,
        );
        let handle = open(child.0.id(), false)?;
        if crate::current_process_elevated()? {
            // An untrusted target must not bypass the elevation guard in terminate.
            let target = ProcessTarget {
                pid: child.0.id(),
                creation_filetime: "1".into(),
                executable: path.to_string_lossy().into_owned(),
                name: "benign-fixture.exe".into(),
                sid: String::new(),
                session_id: 0,
            };
            for (operation, result) in [
                ("inspect", inspect(&handle, target.pid).map(|_| ())),
                ("preview", preview(target.pid, "1").map(|_| ())),
                ("terminate", terminate(&target).map(|_| ())),
            ] {
                let error = match result {
                    Err(error) => error,
                    Ok(()) => {
                        return Err(io::Error::other(format!(
                            "Elevated {operation} was unexpectedly permitted"
                        )));
                    }
                };
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(error.to_string(), "Use the normal user interface");
            }
            assert!(child.0.try_wait()?.is_none());
            eprintln!(
                "Process-control coverage: elevated caller denied by inspect/preview/terminate and child remained alive; successful normal-user termination is not qualified under this token"
            );
        } else {
            let target = inspect(&handle, child.0.id())?;
            assert!(preview(target.pid, "1").is_err());
            let mut wrong = target.clone();
            wrong.creation_filetime = "1".into();
            assert!(terminate(&wrong).is_err());
            assert!(child.0.try_wait()?.is_none());
            assert!(terminate(&target)?);
            assert!(child.0.wait()?.code().is_some());
            eprintln!(
                "Process-control coverage: normal-user exact-instance termination and stale-instance denial qualified"
            );
        }
        drop(handle);
        drop(child);
        std::fs::remove_file(path)?;
        std::fs::remove_dir(dir)?;
        Ok(())
    }
}
