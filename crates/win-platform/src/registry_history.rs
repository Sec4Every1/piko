//! Bounded read-only Run/RunOnce observations. No command expansion or execution.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS, FILETIME,
    },
    System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_EXPAND_SZ,
        REG_SZ,
    },
};
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryValue {
    pub scope_id: String,
    pub value_name: String,
    pub value_type: u32,
    pub data_hex: String,
    pub text: Option<String>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryScope {
    pub id: String,
    pub complete: bool,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub scopes: Vec<RegistryScope>,
    pub values: Vec<RegistryValue>,
}
pub const MAX_VALUES: usize = 1024;
const MAX_BYTES: usize = 512 * 1024;
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: uniquely owned successful RegOpenKeyEx handle, never a predefined hive.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
pub fn scope_ids() -> Vec<String> {
    let mut ids = Vec::new();
    for hive in ["HKLM", "HKCU"] {
        for view in ["64", "32"] {
            for key in ["Run", "RunOnce"] {
                ids.push(format!(
                    r"{hive}:{view}:SOFTWARE\Microsoft\Windows\CurrentVersion\{key}"
                ));
            }
        }
    }
    ids
}
fn stamp(key: &Key) -> io::Result<u64> {
    let mut time = FILETIME::default();
    // SAFETY: owned live query handle, writable FILETIME, all unused/reserved buffers null.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut time,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok((u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime))
}
fn decode(kind: u32, bytes: &[u8]) -> Option<String> {
    if ![REG_SZ, REG_EXPAND_SZ].contains(&kind) || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let (chunks, _) = bytes.as_chunks::<2>();
    let mut units = chunks
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect::<Vec<_>>();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.contains(&0) {
        return None;
    }
    String::from_utf16(&units).ok()
}
fn warn(scope: &mut RegistryScope, message: String) {
    scope.complete = false;
    if scope.warnings.len() < 8 {
        scope.warnings.push(message);
    }
}
pub fn snapshot() -> io::Result<RegistrySnapshot> {
    let mut result = RegistrySnapshot {
        scopes: Vec::new(),
        values: Vec::new(),
    };
    let mut bytes_total = 0usize;
    for (hive, hive_name) in [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")] {
        for (view, access) in [("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] {
            for suffix in ["Run", "RunOnce"] {
                let path = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\{suffix}");
                let mut scope = RegistryScope {
                    id: format!("{hive_name}:{view}:{path}"),
                    complete: true,
                    warnings: Vec::new(),
                };
                let name = path.encode_utf16().chain([0]).collect::<Vec<_>>();
                let mut handle = ptr::null_mut();
                // SAFETY: predefined borrowed hive, terminated fixed path, query-only access; output owned on success.
                let status = unsafe {
                    RegOpenKeyExW(
                        hive,
                        name.as_ptr(),
                        0,
                        KEY_QUERY_VALUE | access,
                        &mut handle,
                    )
                };
                if [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND].contains(&status) {
                    result.scopes.push(scope);
                    continue;
                }
                if status != ERROR_SUCCESS {
                    warn(
                        &mut scope,
                        format!(
                            "Cannot read key: {}",
                            io::Error::from_raw_os_error(status as i32)
                        ),
                    );
                    result.scopes.push(scope);
                    continue;
                }
                let key = Key(handle);
                let before = stamp(&key);
                if let Err(e) = &before {
                    warn(&mut scope, format!("Key timestamp unavailable: {e}"));
                }
                let mut ended = false;
                for index in 0..128u32 {
                    let mut name = [0u16; 512];
                    let mut units = name.len() as u32;
                    let mut data = [0u8; 2048];
                    let mut size = data.len() as u32;
                    let mut kind = 0;
                    // SAFETY: live query handle; bounded writable name/data and length/type outputs; reserved null. Failed/MORE_DATA buffers never consumed.
                    let status = unsafe {
                        RegEnumValueW(
                            key.0,
                            index,
                            name.as_mut_ptr(),
                            &mut units,
                            ptr::null_mut(),
                            &mut kind,
                            data.as_mut_ptr(),
                            &mut size,
                        )
                    };
                    if status == ERROR_NO_MORE_ITEMS {
                        ended = true;
                        break;
                    }
                    if status == ERROR_MORE_DATA {
                        warn(
                            &mut scope,
                            "Value exceeds name/data bound; missing values remain unknown".into(),
                        );
                        continue;
                    }
                    if status != ERROR_SUCCESS {
                        warn(
                            &mut scope,
                            format!(
                                "Value enumeration failed: {}",
                                io::Error::from_raw_os_error(status as i32)
                            ),
                        );
                        break;
                    }
                    if units as usize >= name.len() || size as usize > data.len() {
                        warn(&mut scope, "Unexpected native buffer length".into());
                        break;
                    }
                    let value_name = match String::from_utf16(&name[..units as usize]) {
                        Ok(v) => v,
                        Err(_) => {
                            warn(&mut scope, "Value name is invalid UTF-16".into());
                            continue;
                        }
                    };
                    let raw = &data[..size as usize];
                    let data_hex = raw.iter().map(|v| format!("{v:02x}")).collect::<String>();
                    let text = decode(kind, raw);
                    let value = RegistryValue {
                        scope_id: scope.id.clone(),
                        value_name,
                        value_type: kind,
                        data_hex,
                        text,
                    };
                    let size = serde_json::to_vec(&value).map_err(io::Error::other)?.len();
                    if bytes_total + size > MAX_BYTES || result.values.len() >= MAX_VALUES {
                        warn(&mut scope, "Snapshot byte/count limit reached".into());
                        break;
                    }
                    bytes_total += size;
                    result.values.push(value);
                }
                if !ended {
                    warn(
                        &mut scope,
                        "Key enumeration incomplete; no absence inferred".into(),
                    );
                }
                match (before, stamp(&key)) {
                    (Ok(a), Ok(b)) if a == b => {}
                    _ => warn(
                        &mut scope,
                        "Key changed during enumeration or timestamp unavailable".into(),
                    ),
                }
                result.scopes.push(scope);
            }
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strings_are_bounded_and_never_expanded() {
        assert_eq!(
            decode(REG_EXPAND_SZ, &[37, 0, 88, 0, 37, 0, 0, 0]),
            Some("%X%".into())
        );
        assert_eq!(decode(REG_SZ, &[0, 216]), None);
        assert_eq!(decode(REG_SZ, &[65, 0, 0, 0, 66, 0]), None);
        assert_eq!(decode(REG_SZ, &[1]), None);
    }
    #[test]
    fn native_read_only_snapshot_has_explicit_scopes() -> io::Result<()> {
        let s = snapshot()?;
        assert_eq!(s.scopes.len(), 8);
        assert!(s.values.len() <= MAX_VALUES);
        assert!(s.values.iter().all(|v| v.data_hex.len() <= 4096));
        Ok(())
    }
}
