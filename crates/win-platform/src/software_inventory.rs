//! Read-only, bounded registration metadata. These records do not identify
//! running executables, verify publishers, or grant/revoke application rights.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE,
        KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_SAM_FLAGS, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ,
        RRF_RT_REG_SZ, RRF_ZEROONFAILURE, RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
    },
};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
pub const MAX_ENTRIES_PER_SCOPE: usize = 1024;
pub const MAX_STRING_UNITS: usize = 1024;
pub const MAX_METADATA_BYTES: usize = 512 * 1024;
const MAX_KEY_UNITS: usize = 256;
const MAX_WARNINGS: usize = 32;
const SOURCE: &str = "windows_uninstall_registry";

#[derive(Clone, Debug, serde::Serialize)]
pub struct InstalledSoftware {
    /// Registry location, not an executable identity or trusted product ID.
    pub id: String,
    pub display_name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    /// Unexpanded, unverified installer metadata; never passed to a shell.
    pub install_location: Option<String>,
    /// Installer-declared servicing date (YYYYMMDD), not a verified first install.
    pub install_date: Option<String>,
    pub display_icon: Option<String>,
    pub scope: String,
    pub registry_view: String,
    pub source: String,
    pub uninstall_key: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct InventorySnapshot {
    pub entries: Vec<InstalledSoftware>,
    /// All requested registry locations were read within the bounds. This does
    /// not imply coverage of portable software or all Windows Store packages.
    pub complete: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy)]
struct Scope {
    hive: HKEY,
    hive_name: &'static str,
    name: &'static str,
    view: &'static str,
    access: REG_SAM_FLAGS,
}

impl Scope {
    fn label(self) -> String {
        format!("{} ({} view)", self.hive_name, self.view)
    }
}

/// Reads HKLM's two views and, only when requested, the runtime account's HKCU.
/// Service callers must pass false: the service account's hive is not the
/// viewer's hive. No profile loading or impersonation is performed here.
pub fn inventory(include_user: bool) -> io::Result<InventorySnapshot> {
    let mut scopes = vec![
        Scope {
            hive: HKEY_LOCAL_MACHINE,
            hive_name: "HKEY_LOCAL_MACHINE",
            name: "machine",
            view: "64",
            access: KEY_WOW64_64KEY,
        },
        Scope {
            hive: HKEY_LOCAL_MACHINE,
            hive_name: "HKEY_LOCAL_MACHINE",
            name: "machine",
            view: "32",
            access: KEY_WOW64_32KEY,
        },
    ];
    if include_user {
        scopes.push(Scope {
            hive: HKEY_CURRENT_USER,
            hive_name: "HKEY_CURRENT_USER",
            name: "user",
            view: "native",
            access: 0,
        });
    }
    let mut snapshot = InventorySnapshot {
        entries: Vec::new(),
        complete: true,
        truncated: false,
        warnings: Vec::new(),
    };
    let mut metadata_bytes = 0;
    let mut readable_scopes = 0;
    for scope in scopes {
        match read_scope(scope, &mut snapshot, &mut metadata_bytes) {
            Ok(()) => readable_scopes += 1,
            Err(error) => snapshot.warn(format!("{} unavailable: {error}", scope.label())),
        }
    }
    if readable_scopes == 0 {
        return Err(io::Error::other(format!(
            "installed-software registry inventory unavailable: {}",
            snapshot.warnings.join("; ")
        )));
    }
    snapshot.entries.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    // Enumeration is not atomic. If keys move while being read, expose one
    // registration once without treating its display name as an identity.
    let mut seen = std::collections::HashSet::new();
    snapshot
        .entries
        .retain(|entry| seen.insert(entry.id.clone()));
    Ok(snapshot)
}

impl InventorySnapshot {
    fn warn(&mut self, warning: String) {
        self.complete = false;
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(warning);
        } else if let Some(last) = self.warnings.last_mut() {
            *last = "Further registry warnings omitted; the inventory is partial.".into();
        }
    }

    fn truncate(&mut self, warning: String) {
        self.truncated = true;
        self.warn(warning);
    }
}

/// Only handles successfully returned by RegOpenKeyExW are owned here.
/// Predefined pseudo-handles are never passed to this wrapper.
struct OwnedKey(HKEY);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns a successfully opened HKEY.
        unsafe { RegCloseKey(self.0) };
    }
}

fn open_key(parent: HKEY, path: &str, access: REG_SAM_FLAGS) -> io::Result<OwnedKey> {
    if path.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in key path",
        ));
    }
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key = ptr::null_mut();
    // SAFETY: live/predefined parent, terminated input and writable HKEY output.
    let status = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, access, &mut key) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if key.is_null() {
        return Err(io::Error::other("registry returned a null key"));
    }
    Ok(OwnedKey(key))
}

fn read_scope(
    scope: Scope,
    snapshot: &mut InventorySnapshot,
    metadata_bytes: &mut usize,
) -> io::Result<()> {
    let root = match open_key(
        scope.hive,
        UNINSTALL,
        KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | scope.access,
    ) {
        Ok(key) => key,
        // An absent uninstall branch is a successfully checked empty scope.
        Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => return Ok(()),
        Err(error) => return Err(error),
    };
    for index in 0..=MAX_ENTRIES_PER_SCOPE {
        let mut buffer = [0u16; MAX_KEY_UNITS];
        let mut units = buffer.len() as u32;
        // SAFETY: live HKEY, writable UTF-16 buffer/capacity, unused outputs null.
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index as u32,
                buffer.as_mut_ptr(),
                &mut units,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if index == MAX_ENTRIES_PER_SCOPE {
            snapshot.truncate(format!(
                "{}: enumeration stopped at {MAX_ENTRIES_PER_SCOPE} registrations.",
                scope.label()
            ));
            break;
        }
        if status != ERROR_SUCCESS {
            if status == ERROR_MORE_DATA {
                snapshot.truncate(format!(
                    "{}: oversized registry key omitted.",
                    scope.label()
                ));
                continue;
            }
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let name = match registry_component(&buffer, units as usize) {
            Ok(name) => name,
            Err(error) => {
                snapshot.warn(format!(
                    "{}: invalid registration key: {error}",
                    scope.label()
                ));
                continue;
            }
        };
        let child = match open_key(root.0, &name, KEY_QUERY_VALUE | scope.access) {
            Ok(key) => key,
            Err(error) => {
                snapshot.warn(format!(
                    "{}: registration {name} unavailable: {error}",
                    scope.label()
                ));
                continue;
            }
        };
        let mut read = |field| match read_string(&child, field) {
            Ok(value) => value,
            Err(error) => {
                if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
                    snapshot.truncated = true;
                }
                snapshot.warn(format!(
                    "{}: registration {name}, {field}: {error}",
                    scope.label()
                ));
                None
            }
        };
        let Some(display_name) = read("DisplayName") else {
            // Components without a display name do not appear as named apps.
            continue;
        };
        let publisher = read("Publisher");
        let version = read("DisplayVersion");
        let install_location = read("InstallLocation");
        let install_date = read("InstallDate");
        let display_icon = read("DisplayIcon");
        let uninstall_key = format!(r"{}\{UNINSTALL}\{name}", scope.hive_name);
        let entry = InstalledSoftware {
            id: format!("registry:{}:{}:{uninstall_key}", scope.name, scope.view),
            display_name,
            publisher,
            version,
            install_location,
            install_date,
            display_icon,
            scope: scope.name.into(),
            registry_view: scope.view.into(),
            source: SOURCE.into(),
            uninstall_key,
        };
        let bytes = entry_metadata_bytes(&entry);
        if *metadata_bytes + bytes > MAX_METADATA_BYTES {
            snapshot.truncate(format!(
                "{}: inventory metadata exceeded the {MAX_METADATA_BYTES}-byte budget.",
                scope.label()
            ));
            break;
        }
        *metadata_bytes += bytes;
        snapshot.entries.push(entry);
    }
    Ok(())
}

fn entry_metadata_bytes(entry: &InstalledSoftware) -> usize {
    entry.id.len()
        + entry.display_name.len()
        + entry.publisher.as_deref().map_or(0, str::len)
        + entry.version.as_deref().map_or(0, str::len)
        + entry.install_location.as_deref().map_or(0, str::len)
        + entry.install_date.as_deref().map_or(0, str::len)
        + entry.display_icon.as_deref().map_or(0, str::len)
        + entry.scope.len()
        + entry.registry_view.len()
        + entry.source.len()
        + entry.uninstall_key.len()
}

fn registry_component(buffer: &[u16], units: usize) -> io::Result<String> {
    if units == 0 || units >= MAX_KEY_UNITS || units >= buffer.len() {
        return Err(io::Error::other("invalid key-name length"));
    }
    let value = String::from_utf16(&buffer[..units]).map_err(io::Error::other)?;
    if value.contains(['\\', '/', '\0']) || value.chars().any(char::is_control) {
        return Err(io::Error::other("key name is not one bounded component"));
    }
    Ok(value)
}

fn read_string(key: &OwnedKey, name: &str) -> io::Result<Option<String>> {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut buffer = [0u16; MAX_STRING_UNITS];
    let mut bytes = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: live query-capable HKEY; terminated value name; aligned, fixed
    // buffer sized in bytes. Expansion is disabled, and only string types pass.
    let status = unsafe {
        RegGetValueW(
            key.0,
            ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND | RRF_ZEROONFAILURE,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    decode_registry_string(&buffer, bytes as usize)
}

fn decode_registry_string(buffer: &[u16], bytes: usize) -> io::Result<Option<String>> {
    if bytes < 2
        || !bytes.is_multiple_of(2)
        || bytes > buffer.len() * 2
        || bytes > MAX_STRING_UNITS * 2
    {
        return Err(io::Error::other("invalid registry string length"));
    }
    let value = &buffer[..bytes / 2];
    let Some(end) = value.iter().position(|&unit| unit == 0) else {
        return Err(io::Error::other("unterminated registry string"));
    };
    if value[end..].iter().any(|&unit| unit != 0) {
        return Err(io::Error::other("embedded NUL in registry string"));
    }
    let value = String::from_utf16(&value[..end]).map_err(io::Error::other)?;
    if value.chars().any(char::is_control) {
        return Err(io::Error::other("control character in registry string"));
    }
    let value = value.trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_strings_reject_overflow_invalid_utf16_and_hidden_suffixes() -> io::Result<()> {
        let valid = [b'A' as u16, b'p' as u16, b'p' as u16, 0];
        assert_eq!(decode_registry_string(&valid, 8)?, Some("App".into()));
        assert_eq!(decode_registry_string(&[0], 2)?, None);
        assert!(decode_registry_string(&valid, 9).is_err());
        assert!(decode_registry_string(&valid, 10).is_err());
        assert!(decode_registry_string(&valid[..3], 6).is_err());
        assert!(decode_registry_string(&[0xd800, 0], 4).is_err());
        assert!(decode_registry_string(&[65, 0, 66, 0], 8).is_err());
        assert!(decode_registry_string(&[65, 10, 0], 6).is_err());
        let too_long = vec![65; MAX_STRING_UNITS + 1];
        assert!(decode_registry_string(&too_long, too_long.len() * 2).is_err());
        Ok(())
    }

    #[test]
    fn enumerated_registry_names_cannot_escape_the_uninstall_branch() -> io::Result<()> {
        for invalid in [
            "",
            "Other\\Subkey",
            "Other/Subkey",
            "Hidden\0Suffix",
            "Bad\nName",
        ] {
            let name: Vec<u16> = invalid.encode_utf16().chain(Some(0)).collect();
            assert!(registry_component(&name, name.len() - 1).is_err());
        }
        let valid: Vec<u16> = "{ABC-123}".encode_utf16().chain(Some(0)).collect();
        assert_eq!(registry_component(&valid, valid.len() - 1)?, "{ABC-123}");
        assert!(registry_component(&valid, valid.len() + 1).is_err());
        Ok(())
    }

    #[test]
    fn warning_budget_keeps_partial_status_explicit() {
        let mut snapshot = InventorySnapshot {
            entries: Vec::new(),
            complete: true,
            truncated: false,
            warnings: Vec::new(),
        };
        for _ in 0..100 {
            snapshot.warn("Unavailable registration".into());
        }
        assert!(!snapshot.complete);
        assert_eq!(snapshot.warnings.len(), MAX_WARNINGS);
        assert!(
            snapshot
                .warnings
                .last()
                .is_some_and(|warning| warning.contains("omitted"))
        );
        snapshot.truncate("Metadata budget exceeded".into());
        assert!(snapshot.truncated);
    }

    #[test]
    fn installed_software_read_only_snapshot_is_bounded_and_has_provenance() -> io::Result<()> {
        let snapshot = inventory(true)?;
        assert!(snapshot.entries.len() <= 3 * MAX_ENTRIES_PER_SCOPE);
        assert!(
            snapshot
                .entries
                .iter()
                .map(entry_metadata_bytes)
                .sum::<usize>()
                <= MAX_METADATA_BYTES
        );
        assert!(snapshot.warnings.len() <= MAX_WARNINGS);
        assert!(!snapshot.truncated || !snapshot.complete);
        assert!(snapshot.warnings.is_empty() || !snapshot.complete);
        let mut identities = std::collections::HashSet::new();
        for entry in &snapshot.entries {
            assert!(identities.insert(&entry.id));
            assert!(!entry.display_name.is_empty());
            assert_eq!(entry.source, SOURCE);
            assert!(entry.uninstall_key.contains(&format!(r"\{UNINSTALL}\")));
            assert!(entry.id.starts_with(&format!(
                "registry:{}:{}:",
                entry.scope, entry.registry_view
            )));
        }
        let machine_only = inventory(false)?;
        assert!(
            machine_only
                .entries
                .iter()
                .all(|entry| entry.scope == "machine")
        );
        Ok(())
    }
}
