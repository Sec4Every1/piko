//! Read-only process and TCP observations. Snapshots are not start/exit/packet events.
use std::{
    collections::HashMap,
    io, mem,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, FILETIME, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
};

pub const MAX_PROCESSES: usize = 4096;
pub const MAX_CONNECTIONS: usize = 8192;
const MAX_TABLE_BYTES: usize = 2 * 1024 * 1024;
const WINDOWS_EPOCH: u64 = 116_444_736_000_000_000;

pub use piko_common_model::{ObservationSnapshot, ObservedConnection, ObservedProcess};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        /* SAFETY: owned native handle, closed exactly once. */
        unsafe { CloseHandle(self.0) };
    }
}

fn now() -> io::Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis(),
    )
    .map_err(io::Error::other)
}
pub fn filetime_unix_ms(value: u64) -> Option<i64> {
    value
        .checked_sub(WINDOWS_EPOCH)
        .and_then(|v| i64::try_from(v / 10_000).ok())
}
fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn inspect(pid: u32, name: String, parent_pid: u32) -> ObservedProcess {
    let mut value = ObservedProcess {
        instance_id: None,
        pid,
        parent_pid,
        name,
        executable: None,
        creation_filetime: None,
        sid: None,
        session_id: None,
        access_error: None,
    };
    // SAFETY: query-only rights; returned handle owned for all timing/path/token reads.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        value.access_error = Some(io::Error::last_os_error().to_string());
        return value;
    }
    let process = Handle(process);
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: live process handle and four independent initialized writable structures.
    if unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) } != 0
    {
        let time = ticks(creation);
        if filetime_unix_ms(time).is_some() {
            value.creation_filetime = Some(time);
        }
    } else {
        value.access_error = Some(io::Error::last_os_error().to_string());
    }
    let mut path = [0_u16; 4096];
    let mut count = path.len() as u32;
    // SAFETY: bounded writable UTF-16 buffer, exact capacity, live query handle.
    if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut count) } != 0
        && count as usize <= path.len()
    {
        value.executable = String::from_utf16(&path[..count as usize]).ok();
        if let Some(path) = &value.executable {
            if let Some(name) = path.rsplit('\\').next() {
                value.name = name.to_string();
            }
        }
    } else {
        value.access_error = Some(io::Error::last_os_error().to_string());
    }
    match crate::native::identity_of_process(process.0) {
        Ok(identity) => {
            value.sid = Some(identity.sid);
            value.session_id = Some(identity.session_id);
        }
        Err(error) => value.access_error = Some(error.to_string()),
    }
    value
}
/// Query-only identity/path; partial token access stays explicit in the result.
pub fn inspect_process(pid: u32) -> ObservedProcess {
    inspect(pid, String::new(), 0)
}

fn processes() -> io::Result<(Vec<ObservedProcess>, bool)> {
    // SAFETY: processes only, no target process or inheritance; snapshot uniquely owned.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = Handle(snapshot);
    let mut row = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut rows = Vec::new();
    // SAFETY: initialized exact-size record and live ToolHelp handle.
    let mut found = unsafe { Process32FirstW(snapshot.0, &mut row) };
    while found != 0 {
        if rows.len() >= MAX_PROCESSES {
            return Ok((rows, false));
        }
        let end = row
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(row.szExeFile.len());
        let name = String::from_utf16(&row.szExeFile[..end]).map_err(io::Error::other)?;
        rows.push(inspect(row.th32ProcessID, name, row.th32ParentProcessID));
        // SAFETY: same initialized writable record and live snapshot.
        found = unsafe { Process32NextW(snapshot.0, &mut row) };
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
        return Err(error);
    }
    Ok((rows, true))
}

/// Table allocation is aligned and bounded. Growth races retry at most three times.
fn tcp_table(family: u32) -> io::Result<Vec<u8>> {
    let mut needed = 0;
    // SAFETY: sizing-only call with null table, valid size output, supported owner-PID table.
    let result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut needed,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != ERROR_INSUFFICIENT_BUFFER && result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    for _ in 0..3 {
        if !(4..=MAX_TABLE_BYTES).contains(&(needed as usize)) {
            return Err(io::Error::other("TCP table exceeds byte budget"));
        }
        let mut aligned = vec![0_u64; (needed as usize).div_ceil(8)];
        let capacity = aligned.len() * 8;
        needed = capacity as u32;
        // SAFETY: aligned owned buffer with stated capacity; synchronous API, no pointers retained.
        let result = unsafe {
            GetExtendedTcpTable(
                aligned.as_mut_ptr().cast(),
                &mut needed,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if result == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        if needed as usize > capacity {
            return Err(io::Error::other("TCP size exceeded output buffer"));
        }
        // SAFETY: output lies within the initialized aligned allocation; copy breaks native lifetime.
        return Ok(unsafe {
            std::slice::from_raw_parts(aligned.as_ptr().cast::<u8>(), needed as usize)
        }
        .to_vec());
    }
    Err(io::Error::other(
        "TCP table kept growing during bounded read",
    ))
}

fn parse_tcp(bytes: &[u8], family: u32) -> io::Result<Vec<ObservedConnection>> {
    if bytes.len() < 4 {
        return Err(io::Error::other("Truncated TCP table"));
    }
    let count = u32::from_ne_bytes(bytes[..4].try_into().map_err(io::Error::other)?) as usize;
    let size = match family {
        2 => mem::size_of::<MIB_TCPROW_OWNER_PID>(),
        23 => mem::size_of::<MIB_TCP6ROW_OWNER_PID>(),
        _ => return Err(io::Error::other("Unsupported TCP family")),
    };
    if count > MAX_CONNECTIONS
        || count
            .checked_mul(size)
            .and_then(|v| v.checked_add(4))
            .is_none_or(|v| v > bytes.len())
    {
        return Err(io::Error::other(
            "TCP row count exceeds its buffer or bound",
        ));
    }
    let mut rows = Vec::with_capacity(count);
    for chunk in bytes[4..4 + count * size].chunks_exact(size) {
        let row = if family == 2 {
            // SAFETY: exact checked row-sized bytes; read_unaligned copies a POD native structure.
            let r = unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<MIB_TCPROW_OWNER_PID>()) };
            ObservedConnection {
                pid: r.dwOwningPid,
                process_creation_filetime: None,
                family: "ipv4".into(),
                local_address: Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(),
                local_port: u16::from_be(r.dwLocalPort as u16),
                remote_address: Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes()).to_string(),
                remote_port: u16::from_be(r.dwRemotePort as u16),
                state: r.dwState,
            }
        } else {
            // SAFETY: exact checked row-sized bytes; read_unaligned copies a POD native structure.
            let r = unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<MIB_TCP6ROW_OWNER_PID>()) };
            let address = |ip: [u8; 16], scope: u32| {
                if scope == 0 {
                    Ipv6Addr::from(ip).to_string()
                } else {
                    format!("{}%{scope}", Ipv6Addr::from(ip))
                }
            };
            ObservedConnection {
                pid: r.dwOwningPid,
                process_creation_filetime: None,
                family: "ipv6".into(),
                local_address: address(r.ucLocalAddr, r.dwLocalScopeId),
                local_port: u16::from_be(r.dwLocalPort as u16),
                remote_address: address(r.ucRemoteAddr, r.dwRemoteScopeId),
                remote_port: u16::from_be(r.dwRemotePort as u16),
                state: r.dwState,
            }
        };
        rows.push(row);
    }
    Ok(rows)
}

pub fn observe() -> io::Result<ObservationSnapshot> {
    let started_at_unix_ms = now()?;
    let (mut processes, process_complete) = processes()?;
    let mut connections = Vec::new();
    let mut warnings = Vec::new();
    let mut network_complete = true;
    for family in [2, 23] {
        match tcp_table(family).and_then(|b| parse_tcp(&b, family)) {
            Ok(rows) if connections.len() + rows.len() <= MAX_CONNECTIONS => {
                connections.extend(rows)
            }
            Ok(_) => {
                network_complete = false;
                warnings.push("Combined TCP snapshot exceeds row budget".into());
            }
            Err(error) => {
                network_complete = false;
                warnings.push(format!("TCP family {family}: {error}"));
            }
        }
    }
    let mut udp_endpoints = Vec::new();
    let mut udp_complete = true;
    for family in [2, 23] {
        match crate::udp::read(family) {
            Ok(rows) if udp_endpoints.len() + rows.len() <= MAX_CONNECTIONS => {
                udp_endpoints.extend(rows)
            }
            Ok(_) => {
                udp_complete = false;
                warnings.push("Combined UDP snapshot exceeds row budget".into());
            }
            Err(e) => {
                udp_complete = false;
                warnings.push(format!("UDP family {family}: {e}"));
            }
        }
    }
    if udp_endpoints.len() > 2048 {
        udp_endpoints.truncate(2048);
        udp_complete = false;
        warnings.push("UDP snapshot exceeds API byte budget (2048 rows)".into());
    }
    let mut process_complete = process_complete;
    let mut budget = 0usize;
    processes.retain(|p| {
        let strings = p.name.len()
            + p.executable.as_ref().map_or(0, String::len)
            + p.sid.as_ref().map_or(0, String::len)
            + p.access_error.as_ref().map_or(0, String::len);
        budget = budget.saturating_add(512 + strings * 6);
        if budget > 1024 * 1024 {
            process_complete = false;
            false
        } else {
            true
        }
    });
    if connections.len() > 2048 {
        connections.truncate(2048);
        network_complete = false;
        warnings.push("TCP snapshot exceeds API byte budget (2048 rows)".into());
    }
    let before: HashMap<_, _> = processes
        .iter()
        .filter_map(|p| p.creation_filetime.map(|t| (p.pid, t)))
        .collect();
    let mut verified = HashMap::new();
    for connection in &mut connections {
        let after = verified
            .entry(connection.pid)
            .or_insert_with(|| inspect(connection.pid, String::new(), 0).creation_filetime);
        connection.process_creation_filetime = before
            .get(&connection.pid)
            .copied()
            .filter(|time| Some(*time) == *after);
    }
    for endpoint in &mut udp_endpoints {
        let after = verified
            .entry(endpoint.pid)
            .or_insert_with(|| inspect(endpoint.pid, String::new(), 0).creation_filetime);
        endpoint.process_creation_filetime = before
            .get(&endpoint.pid)
            .copied()
            .filter(|time| Some(*time) == *after);
    }
    // Rows may have raced PID replacement after ToolHelp. Never claim the old parent belongs
    // to a newly queried process created after the snapshot began.
    for process in &mut processes {
        if process
            .creation_filetime
            .and_then(filetime_unix_ms)
            .is_some_and(|t| t > started_at_unix_ms)
        {
            process.parent_pid = 0;
        }
    }
    if !process_complete {
        warnings.push("Process snapshot exceeds row budget".into());
    }
    Ok(ObservationSnapshot {
        started_at_unix_ms,
        completed_at_unix_ms: now()?,
        processes,
        connections,
        udp_endpoints,
        udp_complete: Some(udp_complete),
        process_complete,
        network_complete,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_snapshot_observes_self_without_inventing_protected_process_identity() -> io::Result<()>
    {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        let snapshot = observe()?;
        let process = snapshot
            .processes
            .iter()
            .find(|p| p.pid == std::process::id())
            .ok_or_else(|| io::Error::other("Self missing"))?;
        assert!(process.creation_filetime.is_some());
        assert!(process.executable.is_some());
        assert!(snapshot.udp_endpoints.iter().any(|e| e.pid == process.pid
            && e.local_port == port
            && e.process_creation_filetime == process.creation_filetime));
        assert_eq!(
            process.sid.as_deref(),
            Some(crate::current_identity()?.sid.as_str())
        );
        assert!(snapshot.network_complete, "{:?}", snapshot.warnings);
        assert!(snapshot.connections.len() <= MAX_CONNECTIONS);
        assert_eq!(filetime_unix_ms(WINDOWS_EPOCH), Some(0));
        assert_eq!(filetime_unix_ms(0), None);
        Ok(())
    }
    #[test]
    fn malformed_table_bounds_are_rejected_before_native_row_reads() {
        assert!(parse_tcp(&[], 2).is_err());
        assert!(parse_tcp(&u32::MAX.to_ne_bytes(), 2).is_err());
        assert!(parse_tcp(&1_u32.to_ne_bytes(), 23).is_err());
        assert!(parse_tcp(&0_u32.to_ne_bytes(), 99).is_err());
        assert!(parse_tcp(&0_u32.to_ne_bytes(), 23).is_ok_and(|r| r.is_empty()));
    }
}
