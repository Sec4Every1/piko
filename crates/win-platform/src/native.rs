use std::{ffi::c_void, io, mem, os::windows::io::AsRawHandle, ptr};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenSessionId, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

/// OS-derived identity, never accepted from a JSON request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalIdentity {
    pub sid: String,
    pub session_id: u32,
}

impl LocalIdentity {
    pub fn pipe_name(&self) -> String {
        format!(r"\\.\pipe\piko.dev.v1.{}.{}", self.sid, self.session_id)
    }
}

struct OwnedHandle(HANDLE);
pub fn current_process_elevated() -> io::Result<bool> {
    use windows_sys::Win32::Security::{TokenElevation, TOKEN_ELEVATION};
    let mut token = ptr::null_mut();
    // SAFETY: current-process pseudo handle and valid output, query-only access.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    // SAFETY: live query token and exact writable TOKEN_ELEVATION.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            mem::size_of_val(&elevation) as u32,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != mem::size_of_val(&elevation) {
        return Err(io::Error::other("invalid token elevation size"));
    }
    Ok(elevation.TokenIsElevated != 0)
}
/// Must run synchronously after reading the request, on the same OS thread.
/// Identification-level impersonation queries the actual pipe client's token;
/// no operation is performed using that token.
pub fn authorize_response_client(pipe: &NamedPipeServer) -> io::Result<LocalIdentity> {
    use windows_sys::Win32::{
        Security::{RevertToSelf, TokenElevation, TOKEN_ELEVATION},
        System::{
            Pipes::ImpersonateNamedPipeClient,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    };
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: paired with successful impersonation on this same thread.
            // Continuing with another caller's token would violate authority.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    // SAFETY: connected server pipe has just completed a request read.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = Revert;
    let mut token = ptr::null_mut();
    // SAFETY: current-thread pseudo handle, valid output, query access only.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    // SAFETY: exact writable TOKEN_ELEVATION and owned query handle.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            mem::size_of_val(&elevation) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned as usize != mem::size_of_val(&elevation) || elevation.TokenIsElevated == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "this runtime requires an elevated administrator for response actions",
        ));
    }
    identity_from_token(&token)
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: acquired from a successful OpenProcess/OpenProcessToken;
        // uniquely owned, not a pseudo-handle, and never borrowed past this drop.
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Windows conversion APIs allocate these buffers with LocalAlloc.
        // This owner frees each allocation once, after all borrowed pointers expire.
        unsafe { LocalFree(self.0) };
    }
}

pub fn current_identity() -> io::Result<LocalIdentity> {
    // SAFETY: returns a borrowed process pseudo-handle, never closed by us.
    identity_of_process(unsafe { GetCurrentProcess() })
}

pub(crate) fn identity_of_process(process: HANDLE) -> io::Result<LocalIdentity> {
    let mut token = ptr::null_mut();
    // SAFETY: process is live for the call; out pointer is writable. Only TOKEN_QUERY
    // is requested. Failure leaves no owned handle; success transfers one to owner.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    identity_from_token(&token)
}

fn identity_from_token(token: &OwnedHandle) -> io::Result<LocalIdentity> {
    let mut required = 0u32;
    // SAFETY: the sizing call intentionally supplies a null, zero-length buffer.
    let sized =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    // SAFETY: read the error immediately after the sizing call, on the same thread.
    if sized != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    if required < mem::size_of::<TOKEN_USER>() as u32 || required > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid token buffer size",
        ));
    }
    // usize ensures pointer alignment for TOKEN_USER and its embedded SID pointer.
    let mut buffer = vec![0usize; (required as usize).div_ceil(mem::size_of::<usize>())];
    // SAFETY: aligned writable allocation is at least required bytes, and token is
    // live. The buffer remains alive through the SID conversion below.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser query initializes an aligned TOKEN_USER and SID
    // within the still-live buffer. We only borrow them during this function.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_string = ptr::null_mut();
    // SAFETY: SID comes from the OS token; out pointer is valid and owned on success.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_owner = LocalAllocation(sid_string.cast());
    let mut length = 0;
    // SAFETY: successful API returns a NUL-terminated wide string allocated by
    // Windows. The owner lives until after the copy; no caller-provided pointer.
    while unsafe { *sid_string.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: length was found inside the OS-allocated NUL-terminated string.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, length) })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SID encoding"))?;
    drop(sid_owner);
    let mut session_id = 0u32;
    let mut returned = 0u32;
    // SAFETY: TokenSessionId is a DWORD; exact writable size and live token handle.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenSessionId,
            (&mut session_id as *mut u32).cast(),
            4,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalIdentity { sid, session_id })
}

pub fn create_private_pipe(identity: &LocalIdentity, first: bool) -> io::Result<NamedPipeServer> {
    // Never interpolate a caller-controlled SID into SDDL.
    if *identity != current_identity()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity mismatch",
        ));
    }
    create_pipe(
        &identity.pipe_name(),
        &format!("D:P(A;;GA;;;{})", identity.sid),
        first,
    )
}

fn create_pipe(name: &str, descriptor_text: &str, first: bool) -> io::Result<NamedPipeServer> {
    let sddl: Vec<u16> = descriptor_text.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: input is NUL terminated and lives through the call; the output is a
    // LocalAlloc-owned self-relative security descriptor, freed after pipe creation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let owner = LocalAllocation(descriptor);
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: owner.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(5)
        .in_buffer_size(16384)
        .out_buffer_size(16384);
    // SAFETY: attrs and its security descriptor remain valid until CreateNamedPipe
    // returns. Windows captures the descriptor; Tokio owns the resulting handle.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
}

pub fn valid_sid_text(sid: &str) -> bool {
    sid.len() <= 184
        && sid.starts_with("S-1-")
        && sid[4..].split('-').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u64>().is_ok()
        })
}

pub fn create_service_pipe(viewer_sid: &str, first: bool) -> io::Result<NamedPipeServer> {
    let identity = current_identity()?;
    if identity.session_id != 0
        || !identity.sid.starts_with("S-1-5-80-")
        || !valid_sid_text(viewer_sid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service requires a virtual service account in session 0 and a valid viewer SID",
        ));
    }
    // Medium mandatory label permits the enrolled desktop token to write requests.
    // DACL still grants only that viewer data/read-attributes/synchronize, never CREATE_PIPE_INSTANCE.
    create_pipe(
        super::service::PIPE_NAME,
        &format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{})(A;;0x100083;;;{viewer_sid})S:(ML;;NW;;;ME)",
            identity.sid
        ),
        first,
    )
}

pub fn open_service_pipe(expected_pid: u32) -> io::Result<NamedPipeClient> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };
    let name: Vec<u16> = super::service::PIPE_NAME
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: terminated local name, no inherited security descriptor, specific data
    // access, overlapped handle. Identification prevents server privilege delegation.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x0010_0083,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(231) {
            return Err(error); // Preserve PIPE_BUSY for bounded client retries.
        }
        return Err(io::Error::new(
            error.kind(),
            format!("service pipe open: {error}"),
        ));
    }
    // SAFETY: fresh owned overlapped named pipe handle; ownership transferred exactly
    // once to Tokio (including the error path inside Tokio's registration).
    let pipe = unsafe { NamedPipeClient::from_raw_handle(handle) }?;
    let mut pid = 0;
    // SAFETY: live borrowed connected pipe handle and writable DWORD output.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("service pipe access/authentication: {error}"),
        ));
    }
    if pid != expected_pid || super::service::installed_service_pid()? != Some(pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe server does not match the running SCM service",
        ));
    }
    Ok(pipe)
}

fn authenticate_process(pid: u32, expected: &LocalIdentity) -> io::Result<()> {
    // SAFETY: PID is obtained from the connected pipe, not untrusted JSON. Request
    // read-only identity access, never privilege adjustment or process mutation.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = OwnedHandle(handle);
    let peer = identity_of_process(process.0)?;
    if peer != *expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe peer SID/session mismatch",
        ));
    }
    Ok(())
}

pub fn authenticate_client(pipe: &NamedPipeServer, expected: &LocalIdentity) -> io::Result<()> {
    let mut pid = 0;
    // SAFETY: the borrowed pipe handle remains owned/live; output points to a u32.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    authenticate_process(pid, expected)
}

pub fn authenticate_server(pipe: &NamedPipeClient, expected: &LocalIdentity) -> io::Result<()> {
    let mut pid = 0;
    // SAFETY: the borrowed pipe handle remains owned/live; output points to a u32.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    authenticate_process(pid, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_authority_comes_from_pipe_client_token_and_is_reverted() -> io::Result<()> {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::windows::named_pipe::ClientOptions,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let name = format!(r"\\.\pipe\piko.auth-test.{}", std::process::id());
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)?;
            let mut client = ClientOptions::new().open(&name)?;
            server.connect().await?;
            client.write_u8(42).await?;
            assert_eq!(server.read_u8().await?, 42);
            let identity = current_identity()?;
            let result = authorize_response_client(&server);
            assert_eq!(result.is_ok(), current_process_elevated()?);
            assert_eq!(identity, current_identity()?);
            Ok(())
        })
    }

    #[test]
    fn service_viewer_sid_cannot_inject_an_access_rule() {
        assert!(valid_sid_text("S-1-5-21-123-456-789-1001"));
        for invalid in [
            "S-1-5-21)(A;;GA;;;WD)",
            "S-1-5--21",
            "S-1-",
            "WD",
            "S-1-5-foo",
        ] {
            assert!(!valid_sid_text(invalid));
        }
    }

    #[test]
    fn identity_is_os_derived_and_stable() -> io::Result<()> {
        let first = current_identity()?;
        assert!(first.sid.starts_with("S-1-"));
        assert_eq!(first, current_identity()?);
        Ok(())
    }

    #[test]
    fn private_pipe_rejects_wrong_identity_and_duplicate_first_instance() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut identity = current_identity()?;
            identity.session_id = identity.session_id.wrapping_add(1);
            assert!(create_private_pipe(&identity, true).is_err());
            identity = current_identity()?;
            let _pipe = create_private_pipe(&identity, true)?;
            assert!(create_private_pipe(&identity, true).is_err());
            Ok(())
        })
    }
}
