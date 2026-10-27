//! Opt-in, fixed HKCU Run entry. Never edits another installation's command.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RRF_NOEXPAND,
        RRF_RT_REG_SZ, RegCloseKey, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    },
};
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE: &str = "PikoMonitor";
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this handle is owned by this wrapper.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn open(write: bool) -> io::Result<Option<Key>> {
    let mut key = ptr::null_mut();
    // SAFETY: fixed root, terminated key name, valid output.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(KEY).as_ptr(),
            0,
            KEY_QUERY_VALUE | if write { KEY_SET_VALUE } else { 0 },
            &mut key,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(Some(Key(key)))
}
#[derive(serde::Serialize)]
pub struct StartupStatus {
    pub enabled: bool,
    pub conflict: bool,
    pub command: String,
}
pub fn command(path: &std::path::Path) -> io::Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::other("Startup path is not Unicode"))?;
    if !std::path::Path::new(path).is_absolute()
        || path.chars().any(|c| c.is_control() || c == '"' || c == '%')
    {
        return Err(io::Error::other("Invalid startup path"));
    }
    let command = format!("\"{path}\" --monitor-only");
    if command.encode_utf16().count() > 260 {
        return Err(io::Error::other(
            "Startup command exceeds the Windows 260-character limit",
        ));
    }
    Ok(command)
}
fn read(key: &Key) -> io::Result<Option<String>> {
    let mut buf = [0u16; 1024];
    let mut bytes = std::mem::size_of_val(&buf) as u32;
    // SAFETY: owned key, fixed terminated value name, bounded writable buffer.
    let code = unsafe {
        RegGetValueW(
            key.0,
            ptr::null(),
            wide(VALUE).as_ptr(),
            RRF_RT_REG_SZ | RRF_NOEXPAND,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if bytes < 2 || !bytes.is_multiple_of(2) {
        return Err(io::Error::other("Invalid startup registry value"));
    }
    let units = bytes as usize / 2;
    if buf[units - 1] != 0 || buf[..units - 1].contains(&0) {
        return Err(io::Error::other("Invalid startup registry string"));
    }
    String::from_utf16(&buf[..units - 1])
        .map(Some)
        .map_err(io::Error::other)
}
pub fn status(path: &std::path::Path) -> io::Result<StartupStatus> {
    let command = command(path)?;
    let configured = open(false)?.map(|key| read(&key)).transpose()?.flatten();
    Ok(StartupStatus {
        enabled: configured.as_ref() == Some(&command),
        conflict: configured.is_some() && configured.as_ref() != Some(&command),
        command,
    })
}
pub fn set(path: &std::path::Path, enabled: bool) -> io::Result<StartupStatus> {
    if crate::current_process_elevated()? {
        return Err(io::Error::other("Use a normal user session"));
    }
    let command = command(path)?;
    let key = open(true)?.ok_or_else(|| io::Error::other("Windows Run key is unavailable"))?;
    if read(&key)?.is_some_and(|current| current != command) {
        return Err(io::Error::other(
            "Another startup command exists; manage PikoMonitor in Windows before changing it",
        ));
    }
    let name = wide(VALUE);
    let data = wide(&command);
    // SAFETY: owned key, fixed value, terminated UTF-16 and exact byte length.
    let code = unsafe {
        if enabled {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        } else {
            RegDeleteValueW(key.0, name.as_ptr())
        }
    };
    if code != ERROR_SUCCESS && (code != ERROR_FILE_NOT_FOUND || enabled) {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    status(path)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_command_is_bounded() -> io::Result<()> {
        assert_eq!(
            command(std::path::Path::new(r"C:\piko\piko-desktop.exe"))?,
            r#""C:\piko\piko-desktop.exe" --monitor-only"#
        );
        assert!(command(std::path::Path::new("relative.exe")).is_err());
        assert!(command(std::path::Path::new(r"C:\bad%path\piko.exe")).is_err());
        assert!(
            command(std::path::Path::new(&format!(
                "C:\\{}.exe",
                "x".repeat(260)
            )))
            .is_err()
        );
        Ok(())
    }
}
