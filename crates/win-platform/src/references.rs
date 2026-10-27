//! Browser references explicitly chosen by the UI user; never a general URL or shell API.
use std::{io, ptr};
use windows_sys::Win32::{
    System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    },
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
};

fn attack_url(technique: &str) -> io::Result<&'static str> {
    match technique {
        "T1685.005" => Ok("https://attack.mitre.org/techniques/T1685/005/"),
        "T1685.001" => Ok("https://attack.mitre.org/techniques/T1685/001/"),
        "T1136" => Ok("https://attack.mitre.org/techniques/T1136/"),
        "T1098" => Ok("https://attack.mitre.org/techniques/T1098/"),
        "T1053.005" => Ok("https://attack.mitre.org/techniques/T1053/005/"),
        "T1110" => Ok("https://attack.mitre.org/techniques/T1110/"),
        "T1685" => Ok("https://attack.mitre.org/techniques/T1685/"),
        "T1543.003" => Ok("https://attack.mitre.org/techniques/T1543/003/"),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unknown ATT&CK reference",
        )),
    }
}

/// Opens one of seven compiled-in HTTPS pages in the default browser, without elevation.
/// Call from a blocking worker: COM initialization and cleanup stay on the same thread.
pub fn open_attack_reference(technique: &str) -> io::Result<()> {
    let url: Vec<u16> = attack_url(technique)?
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    // SAFETY: null reserved pointer and documented STA flags; no application memory is retained.
    let initialized = unsafe {
        CoInitializeEx(
            ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if initialized < 0 {
        return Err(io::Error::other(format!(
            "Browser COM initialization failed: {initialized:#x}"
        )));
    }
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            // SAFETY: balances exactly this function's successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
    let _com = ComGuard;
    // SAFETY: strings are terminated, live for the call and compiled-in. No arguments,
    // arbitrary path, user URL or runas verb is accepted. The result is not an owned handle.
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            url.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if result <= 32 {
        return Err(io::Error::other(format!(
            "Windows could not open the reference (ShellExecute {result})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_references_reject_paths_urls_and_modified_ids_before_effects() {
        for id in [
            "T1685.005",
            "T1685.001",
            "T1543.003",
            "T1136",
            "T1098",
            "T1053.005",
            "T1685",
            "T1110",
        ] {
            assert!(attack_url(id)
                .is_ok_and(|url| url.starts_with("https://attack.mitre.org/techniques/")));
        }
        for value in [
            "",
            "T1685.005 ",
            "T1685.005\0",
            "t1685.005",
            "https://attack.mitre.org/",
            "file:///C:/Windows/System32/cmd.exe",
            "T1685.005&calc",
            "T1543.003/../../",
        ] {
            assert!(open_attack_reference(value)
                .is_err_and(|error| error.kind() == io::ErrorKind::InvalidInput));
        }
    }
}
