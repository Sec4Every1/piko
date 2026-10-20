//! Embedded Authenticode policy, local cache only. Not malware/reputation/CVE analysis.
use std::{fs::File, io, os::windows::io::AsRawHandle};
use windows_sys::Win32::Security::Cryptography::Catalog::*;
use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, Security::WinTrust::*};

/// Read-only catalog fallback, SHA-256, same borrowed locked member file.
/// Positive result means local signing policy, never malware/revocation clearance.
pub fn verify_local(file: &File, path: &str) -> io::Result<Option<&'static str>> {
    let status = verify_embedded(file, path)?;
    if status == 0 {
        return Ok(Some("embedded_local"));
    }
    if status as u32 != 0x800B0100 {
        return Ok(None);
    }
    struct Admin(isize);
    impl Drop for Admin {
        fn drop(&mut self) {
            // SAFETY: unique context successfully acquired below, last use completed.
            unsafe {
                CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }
    struct Catalog<'a> {
        admin: &'a Admin,
        handle: isize,
    }
    impl Drop for Catalog<'_> {
        fn drop(&mut self) {
            // SAFETY: unique enumeration result, released before its admin context.
            unsafe {
                CryptCATAdminReleaseCatalogContext(self.admin.0, self.handle, 0);
            }
        }
    }
    let algorithm: Vec<u16> = "SHA256".encode_utf16().chain(Some(0)).collect();
    let mut admin = 0;
    // SAFETY: writable handle output, terminated algorithm, default subsystem/policy.
    if unsafe {
        CryptCATAdminAcquireContext2(
            &mut admin,
            std::ptr::null(),
            algorithm.as_ptr(),
            std::ptr::null(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let admin = Admin(admin);
    let mut hash_len = 0;
    // SAFETY: sizing call on the borrowed live file, no output allocation yet.
    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            file.as_raw_handle().cast(),
            &mut hash_len,
            std::ptr::null_mut(),
            0,
        )
    } == 0
        || hash_len != 32
    {
        return Err(io::Error::other("Catalog SHA-256 sizing failed"));
    }
    let mut hash = [0u8; 32];
    // SAFETY: exactly 32 writable bytes, bounded size output, same live file/context.
    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            file.as_raw_handle().cast(),
            &mut hash_len,
            hash.as_mut_ptr(),
            0,
        )
    } == 0
        || hash_len != 32
    {
        return Err(io::Error::other("Catalog SHA-256 failed"));
    }
    // SAFETY: bounded SHA-256 bytes, first installed catalog only, no prior handle.
    let catalog = unsafe {
        CryptCATAdminEnumCatalogFromHash(admin.0, hash.as_ptr(), 32, 0, std::ptr::null_mut())
    };
    if catalog == 0 {
        return Ok(None);
    }
    let catalog = Catalog {
        admin: &admin,
        handle: catalog,
    };
    let mut info = CATALOG_INFO {
        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    // SAFETY: exact initialized structure, owned live catalog handle.
    if unsafe { CryptCATCatalogInfoFromContext(catalog.handle, &mut info, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !info.wszCatalogFile.iter().any(|c| *c == 0) {
        return Err(io::Error::other("Unterminated catalog path"));
    }
    let member_tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
    let tag: Vec<u16> = member_tag.encode_utf16().chain(Some(0)).collect();
    let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut member = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
        pcwszMemberTag: tag.as_ptr(),
        pcwszMemberFilePath: name.as_ptr(),
        hMemberFile: file.as_raw_handle().cast(),
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: 32,
        hCatAdmin: admin.0,
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut member,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: union discriminant matches catalog; all borrowed buffers/handles
    // outlive both synchronous calls. No UI, URL retrieval or catalog writes.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: close the exact provider state even on a failed verification.
    let close = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if close != 0 {
        return Err(io::Error::other("Catalog provider cleanup failed"));
    }
    Ok((status == 0).then_some("catalog_local"))
}
pub fn verify_embedded(file: &File, path: &str) -> io::Result<i32> {
    if path.encode_utf16().count() > 4096 || path.contains('\0') {
        return Err(io::Error::other("Invalid signature path"));
    }
    let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: name.as_ptr(),
        hFile: file.as_raw_handle().cast(),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: exact sized native structs, live borrowed read-only file and terminated path,
    // union matches WTD_CHOICE_FILE. No UI, execution or URL retrieval is allowed.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same action/struct, closes native state even after verification failure;
    // the borrowed file handle is owned by the Rust caller and remains open.
    let closed = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if closed != 0 {
        return Err(io::Error::other(format!(
            "Signature provider close failed: 0x{:08X}",
            closed as u32
        )));
    }
    Ok(status)
}
