//! Explicit AppContainer trials of staged copies; no host-wide permission policy.
//! All handles and profile names are owned. Failure never falls back to normal execution.
use serde::{Deserialize, Serialize};
use std::{fs::File, io, mem, os::windows::io::AsRawHandle, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
        },
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, FreeSid,
        GetSecurityDescriptorDacl, GetTokenInformation,
        Isolation::{
            CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath,
        },
        PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
        TOKEN_GROUPS, TOKEN_QUERY, TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
        WinCapabilityInternetClientSid,
    },
    System::{Com::CoTaskMemFree, JobObjects::*, Threading::*},
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

pub const MEMORY_LIMIT_BYTES: usize = 512 * 1024 * 1024;
pub const PROCESS_LIMIT: u32 = 1;
const GROUP_ENABLED: u32 = 4; // SE_GROUP_ENABLED, required by SECURITY_CAPABILITIES.

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    #[default]
    None,
    InternetClient,
}
impl NetworkAccess {
    pub fn capability_count(self) -> u32 {
        match self {
            Self::None => 0,
            Self::InternetClient => 1,
        }
    }
}

struct InternetCapability {
    sid: [usize; 16],
    length: usize,
}
impl InternetCapability {
    fn new() -> io::Result<Self> {
        let mut capability = Self {
            sid: [0; 16],
            length: 0,
        };
        let mut bytes = mem::size_of_val(&capability.sid) as u32;
        // SAFETY: fixed well-known capability; aligned bounded caller-owned SID storage.
        checked(unsafe {
            CreateWellKnownSid(
                WinCapabilityInternetClientSid,
                ptr::null_mut(),
                capability.sid.as_mut_ptr().cast(),
                &mut bytes,
            )
        })?;
        if bytes < 8 || bytes as usize > mem::size_of_val(&capability.sid) {
            return Err(io::Error::other("Invalid internetClient capability SID"));
        }
        capability.length = bytes as usize;
        Ok(capability)
    }
}

fn verify_capabilities(
    buffer: &[usize],
    returned_bytes: usize,
    network: NetworkAccess,
    internet: &InternetCapability,
) -> io::Result<()> {
    let bad = || io::Error::other("Unexpected AppContainer capabilities");
    if returned_bytes < 4 || returned_bytes > mem::size_of_val(buffer) {
        return Err(bad());
    }
    let count = buffer[0] as u32;
    if count != network.capability_count() {
        return Err(bad());
    }
    if count == 0 {
        return Ok(());
    }
    let offset = mem::offset_of!(TOKEN_GROUPS, Groups);
    if returned_bytes < offset + mem::size_of::<SID_AND_ATTRIBUTES>() {
        return Err(bad());
    }
    // SAFETY: TOKEN_GROUPS entry offset has native alignment; size checked above.
    let group = unsafe {
        ptr::read(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>(),
        )
    };
    // Windows may also mark the enabled group mandatory/enabled-by-default.
    // Deny-only, integrity, owner and all other attributes are refused.
    if group.Attributes & GROUP_ENABLED == 0 || group.Attributes & !7 != 0 {
        return Err(bad());
    }
    let base = buffer.as_ptr() as usize;
    let position = (group.Sid as usize).checked_sub(base).ok_or_else(bad)?;
    if position > returned_bytes || internet.length > returned_bytes - position {
        return Err(bad());
    }
    // SAFETY: SID lies wholly in the returned buffer. Exact bytes avoid following
    // an unvalidated SID pointer through any additional native calls.
    let actual = unsafe { std::slice::from_raw_parts(group.Sid.cast::<u8>(), internet.length) };
    let expected =
        unsafe { std::slice::from_raw_parts(internet.sid.as_ptr().cast::<u8>(), internet.length) };
    if actual != expected {
        return Err(bad());
    }
    Ok(())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn local_app_data() -> io::Result<String> {
    let mut folder = ptr::null_mut();
    // SAFETY: fixed documented folder GUID and current-user token; OS allocates output.
    let hr =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut folder) };
    if hr < 0 {
        return Err(io::Error::other(format!(
            "SHGetKnownFolderPath HRESULT {hr:#x}"
        )));
    }
    let decoded = (|| {
        let mut length = 0;
        while length < 32768 && unsafe { *folder.add(length) } != 0 {
            length += 1;
        }
        if length == 32768 {
            return Err(io::Error::other("Local app-data path exceeds limit"));
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(folder, length) })
            .map_err(io::Error::other)
    })();
    unsafe {
        CoTaskMemFree(folder.cast());
    }
    decoded
}
fn checked(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
// HANDLE values are process-wide kernel handles without thread affinity. Integer storage
// keeps raw pointers confined to calls; ownership never leaves these wrappers.
struct Handle(usize);
impl Handle {
    fn new(value: HANDLE) -> io::Result<Self> {
        if value.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(value as usize))
        }
    }
    fn raw(&self) -> HANDLE {
        self.0 as HANDLE
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
}
struct Local(usize);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0 as *mut _);
        }
    }
}

pub struct Profile {
    name: Vec<u16>,
    sid: usize,
    sid_text: String,
    deleted: bool,
    pub data_directory: std::path::PathBuf,
}
impl Profile {
    /// Name is generated by piko from a UUID; an existing profile is never reused.
    pub fn create(id: &str) -> io::Result<Self> {
        if id.len() != 36
            || !id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err(io::Error::other("Invalid restricted session UUID"));
        }
        if crate::current_process_elevated()? {
            return Err(io::Error::other(
                "Restricted trials require a normal user session",
            ));
        }
        let name = wide(&format!("Piko.Trial.{id}"));
        let mut sid = ptr::null_mut();
        // SAFETY: terminated owned strings, no capabilities, valid SID output.
        let hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                wide("piko isolated trial").as_ptr(),
                wide("Staged copy, one process").as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            )
        };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "CreateAppContainerProfile HRESULT {hr:#x}"
            )));
        }
        let mut profile = Self {
            name,
            sid: sid as usize,
            sid_text: String::new(),
            deleted: false,
            data_directory: std::path::PathBuf::new(),
        };
        let mut text = ptr::null_mut();
        // SAFETY: OS-issued SID remains owned by profile; output allocated by Windows.
        checked(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
        let _allocation = Local(text as usize);
        let mut len = 0;
        while len < 192 && unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        if len == 192 {
            return Err(io::Error::other("AppContainer SID exceeds limit"));
        }
        profile.sid_text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
            .map_err(io::Error::other)?;
        let mut folder = ptr::null_mut();
        let hr =
            unsafe { GetAppContainerFolderPath(wide(&profile.sid_text).as_ptr(), &mut folder) };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "GetAppContainerFolderPath HRESULT {hr:#x}"
            )));
        }
        let decoded = (|| {
            let mut length = 0;
            while length < 32768 && unsafe { *folder.add(length) } != 0 {
                length += 1;
            }
            if length == 32768 {
                return Err(io::Error::other("AppContainer profile path exceeds limit"));
            }
            String::from_utf16(unsafe { std::slice::from_raw_parts(folder, length) })
                .map_err(io::Error::other)
        })();
        unsafe {
            CoTaskMemFree(folder.cast());
        }
        profile.data_directory = decoded?.into();
        Ok(profile)
    }
    /// Replace DACL only on a newly created piko staging object opened with WRITE_DAC.
    /// The caller holds its path parents and must never pass original/host resources.
    pub fn protect_staging(&self, file: &File) -> io::Result<()> {
        let user = crate::current_identity()?.sid;
        let sddl = wide(&format!(
            "D:P(A;;FA;;;SY)(A;;FA;;;{user})(A;;GRGX;;;{})",
            self.sid_text
        ));
        let mut descriptor = ptr::null_mut();
        // SAFETY: SID strings originated from Windows; conversion owns output.
        checked(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        })?;
        let _descriptor = Local(descriptor as usize);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        checked(unsafe {
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
        })?;
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other("Missing staging DACL"));
        }
        // SAFETY: valid owned file handle, live descriptor-backed DACL, no SACL/owner edits.
        let result = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Ok(())
    }
    pub fn remove(&mut self) -> io::Result<()> {
        if !self.deleted {
            // SAFETY: profile was newly created by this wrapper, never an existing name.
            let hr = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
            if hr < 0 {
                return Err(io::Error::other(format!(
                    "DeleteAppContainerProfile HRESULT {hr:#x}"
                )));
            }
            self.deleted = true;
        }
        Ok(())
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = self.remove();
        unsafe {
            FreeSid(self.sid as *mut _);
        }
    }
}

struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: documented sizing call; then bounded, usize-aligned backing storage.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 64 * 1024 {
            return Err(io::Error::other("Invalid process attribute size"));
        }
        let mut value = Self {
            storage: vec![0; bytes.div_ceil(mem::size_of::<usize>())],
            initialized: false,
        };
        checked(unsafe { InitializeProcThreadAttributeList(value.raw(), count, 0, &mut bytes) })?;
        value.initialized = true;
        Ok(value)
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn set<T>(&mut self, attribute: u32, value: &T) -> io::Result<()> {
        // SAFETY: caller keeps each typed attribute alive through CreateProcessW.
        checked(unsafe {
            UpdateProcThreadAttribute(
                self.raw(),
                0,
                attribute as usize,
                (value as *const T).cast(),
                mem::size_of::<T>(),
                ptr::null_mut(),
                ptr::null(),
            )
        })
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.raw());
            }
        }
    }
}

pub struct TrialProcess {
    job: Handle,
    process: Handle,
    pub pid: u32,
}
impl Drop for TrialProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
impl TrialProcess {
    pub fn running(&self) -> io::Result<bool> {
        // SAFETY: owned process handle; nonblocking check, PID is not used for authority.
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_OBJECT_0 => Ok(false),
            WAIT_TIMEOUT => Ok(true),
            _ => Err(io::Error::last_os_error()),
        }
    }
    pub fn stop(&self) -> io::Result<()> {
        // SAFETY: job handle owns only the trial created below, never another process.
        checked(unsafe { TerminateJobObject(self.job.raw(), 1) })?;
        match unsafe { WaitForSingleObject(self.process.raw(), 5000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Restricted process did not stop",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
pub fn launch(profile: &Profile, executable: &Path, directory: &Path) -> io::Result<TrialProcess> {
    launch_with_network(profile, executable, directory, NetworkAccess::None)
}

pub fn launch_with_network(
    profile: &Profile,
    executable: &Path,
    directory: &Path,
    network: NetworkAccess,
) -> io::Result<TrialProcess> {
    let path = executable
        .to_str()
        .ok_or_else(|| io::Error::other("Non-Unicode staged path"))?;
    if !executable.is_absolute() || path.contains('"') || path.chars().any(char::is_control) {
        return Err(io::Error::other("Invalid staged path"));
    }
    let app = wide(path);
    let mut command = wide(&format!("\"{path}\""));
    let directory = wide(
        directory
            .to_str()
            .ok_or_else(|| io::Error::other("Non-Unicode directory"))?,
    );
    // Do not expose the parent's environment (which can contain API keys or other secrets).
    let windows = crate::network_elevation::windows_directory()?;
    let data = profile.data_directory.to_string_lossy();
    let environment = [
        // Windows appends Packages/<moniker>/AC when building the AppContainer environment.
        format!("LOCALAPPDATA={}", local_app_data()?),
        format!("PATH={}\\System32", windows.display()),
        format!("SystemRoot={}", windows.display()),
        format!("TEMP={data}\\Temp"),
        format!("TMP={data}\\Temp"),
        format!("WINDIR={}", windows.display()),
    ]
    .join("\0");
    let environment: Vec<u16> = environment.encode_utf16().chain([0, 0]).collect();
    // SAFETY: anonymous, non-inheritable job owned by this call.
    let job = Handle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits.BasicLimitInformation.ActiveProcessLimit = PROCESS_LIMIT;
    limits.ProcessMemoryLimit = MEMORY_LIMIT_BYTES;
    checked(unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            mem::size_of_val(&limits) as u32,
        )
    })?;
    let mut internet = InternetCapability::new()?;
    let mut network_sid = SID_AND_ATTRIBUTES {
        Sid: internet.sid.as_mut_ptr().cast(),
        Attributes: GROUP_ENABLED,
    };
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid as *mut _,
        Capabilities: if network == NetworkAccess::InternetClient {
            &mut network_sid
        } else {
            ptr::null_mut()
        },
        CapabilityCount: network.capability_count(),
        Reserved: 0,
    };
    let child_policy = 1u32; // PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
    let jobs = [job.raw()];
    let mut attributes = Attributes::new(3)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.raw();
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: terminated explicit application/command, no shell or inherited handles.
    // Job/AppContainer are applied atomically by Windows; start suspended to inspect token.
    checked(unsafe {
        CreateProcessW(
            app.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    })?;
    let process = Handle::new(info.hProcess)?;
    let thread = Handle::new(info.hThread)?;
    let mut token = ptr::null_mut();
    let check = (|| {
        checked(unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut token) })?;
        let token = Handle::new(token)?;
        let mut is_container = 0u32;
        let mut bytes = 0;
        checked(unsafe {
            GetTokenInformation(
                token.raw(),
                TokenIsAppContainer,
                (&mut is_container as *mut u32).cast(),
                4,
                &mut bytes,
            )
        })?;
        if is_container != 1 || bytes != 4 {
            return Err(io::Error::other("AppContainer token was not applied"));
        }
        // TokenAppContainerSid embeds a pointer into the returned aligned buffer.
        let mut sid_buffer = [0usize; 128];
        checked(unsafe {
            GetTokenInformation(
                token.raw(),
                TokenAppContainerSid,
                sid_buffer.as_mut_ptr().cast(),
                mem::size_of_val(&sid_buffer) as u32,
                &mut bytes,
            )
        })?;
        let actual_sid = sid_buffer[0] as *mut std::ffi::c_void;
        if actual_sid.is_null() || unsafe { EqualSid(actual_sid, profile.sid as *mut _) } == 0 {
            return Err(io::Error::other("Unexpected AppContainer SID"));
        }
        let mut capability_buffer = [0usize; 128];
        checked(unsafe {
            GetTokenInformation(
                token.raw(),
                TokenCapabilities,
                capability_buffer.as_mut_ptr().cast(),
                mem::size_of_val(&capability_buffer) as u32,
                &mut bytes,
            )
        })?;
        verify_capabilities(&capability_buffer, bytes as usize, network, &internet)?;
        let mut in_job = 0;
        checked(unsafe { IsProcessInJob(process.raw(), job.raw(), &mut in_job) })?;
        if in_job == 0 {
            return Err(io::Error::other("Restricted job was not applied"));
        }
        if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if let Err(error) = check {
        unsafe {
            TerminateJobObject(job.raw(), 1);
            WaitForSingleObject(process.raw(), 5000);
        }
        return Err(error);
    }
    Ok(TrialProcess {
        job,
        process,
        pid: info.dwProcessId,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_capability(buffer: &mut [usize], sid: &[u8], attributes: u32) -> usize {
        buffer.fill(0);
        buffer[0] = 1;
        let group_offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        let sid_offset = group_offset + mem::size_of::<SID_AND_ATTRIBUTES>();
        assert!(sid_offset + sid.len() <= mem::size_of_val(buffer));
        // SAFETY: aligned native group slot and SID bytes fit in the test buffer.
        unsafe {
            let base = buffer.as_mut_ptr().cast::<u8>();
            ptr::copy_nonoverlapping(sid.as_ptr(), base.add(sid_offset), sid.len());
            ptr::write(
                base.add(group_offset).cast::<SID_AND_ATTRIBUTES>(),
                SID_AND_ATTRIBUTES {
                    Sid: base.add(sid_offset).cast(),
                    Attributes: attributes,
                },
            );
        }
        sid_offset + sid.len()
    }

    #[test]
    fn capability_verification_requires_exact_enabled_internet_sid() -> io::Result<()> {
        let internet = InternetCapability::new()?;
        // SAFETY: initialized fixed well-known SID bytes owned by this test.
        let sid = unsafe {
            std::slice::from_raw_parts(internet.sid.as_ptr().cast::<u8>(), internet.length)
        };
        assert_eq!(sid, &[1, 2, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, 1, 0, 0, 0]);
        let mut buffer = [0usize; 128];
        assert!(verify_capabilities(&buffer, 4, NetworkAccess::None, &internet).is_ok());
        assert!(verify_capabilities(&buffer, 3, NetworkAccess::None, &internet).is_err());
        assert!(verify_capabilities(&buffer, 4, NetworkAccess::InternetClient, &internet).is_err());
        let length = token_capability(&mut buffer, sid, GROUP_ENABLED);
        assert!(
            verify_capabilities(&buffer, length, NetworkAccess::InternetClient, &internet).is_ok()
        );
        assert!(verify_capabilities(&buffer, length, NetworkAccess::None, &internet).is_err());
        buffer[0] = 2;
        assert!(
            verify_capabilities(&buffer, length, NetworkAccess::InternetClient, &internet).is_err()
        );
        for attributes in [0, 2, 0x14, 0x24, u32::MAX] {
            let length = token_capability(&mut buffer, sid, attributes);
            assert!(
                verify_capabilities(&buffer, length, NetworkAccess::InternetClient, &internet)
                    .is_err()
            );
        }
        let mut other_sid = sid.to_vec();
        *other_sid
            .last_mut()
            .ok_or_else(|| io::Error::other("empty test SID"))? = 1;
        let length = token_capability(&mut buffer, &other_sid, GROUP_ENABLED);
        assert!(
            verify_capabilities(&buffer, length, NetworkAccess::InternetClient, &internet).is_err()
        );
        let length = token_capability(&mut buffer, sid, GROUP_ENABLED);
        let offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        // SAFETY: test writes only the aligned existing group slot.
        unsafe {
            (*buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>())
            .Sid = ptr::null_mut();
        }
        assert!(
            verify_capabilities(&buffer, length, NetworkAccess::InternetClient, &internet).is_err()
        );
        Ok(())
    }

    #[test]
    fn invalid_names_do_not_create_profiles() {
        for name in [
            "",
            "existing",
            "../../outside",
            "00000000-0000-0000-0000-00000000000z",
        ] {
            assert!(Profile::create(name).is_err());
        }
    }
    #[test]
    fn attributes_are_bounded_and_clean_up_without_launch() -> io::Result<()> {
        let _list = Attributes::new(3)?;
        assert_eq!(PROCESS_LIMIT, 1);
        assert_eq!(MEMORY_LIMIT_BYTES, 536870912);
        Ok(())
    }
}
