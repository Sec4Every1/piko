//! Query-only local UDP binds. Owner PID is verified separately against process lifetime.
use piko_common_model::ObservedUdpEndpoint;
use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    },
};
const MAX_BYTES: usize = 2 * 1024 * 1024;
fn table(family: u32) -> io::Result<Vec<u8>> {
    let mut needed = 0;
    // SAFETY: size probe only, valid family/class and reserved zero; synchronous API.
    let result = unsafe {
        GetExtendedUdpTable(
            ptr::null_mut(),
            &mut needed,
            0,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if result != ERROR_INSUFFICIENT_BUFFER && result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    for _ in 0..3 {
        if !(4..=MAX_BYTES).contains(&(needed as usize)) {
            return Err(io::Error::other("UDP table exceeds byte budget"));
        }
        let mut aligned = vec![0u64; (needed as usize).div_ceil(8)];
        let capacity = aligned.len() * 8;
        needed = capacity as u32;
        // SAFETY: owned initialized aligned allocation with exact capacity; API retains no pointer.
        let result = unsafe {
            GetExtendedUdpTable(
                aligned.as_mut_ptr().cast(),
                &mut needed,
                0,
                family,
                UDP_TABLE_OWNER_PID,
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
            return Err(io::Error::other("UDP size exceeds allocation"));
        }
        // SAFETY: native success and checked output byte count inside live allocation.
        return Ok(unsafe {
            std::slice::from_raw_parts(aligned.as_ptr().cast::<u8>(), needed as usize)
        }
        .to_vec());
    }
    Err(io::Error::other(
        "UDP table kept growing during bounded read",
    ))
}
fn parse(bytes: &[u8], family: u32) -> io::Result<Vec<ObservedUdpEndpoint>> {
    if bytes.len() < 4 {
        return Err(io::Error::other("Truncated UDP header"));
    }
    let count = u32::from_ne_bytes(bytes[..4].try_into().map_err(io::Error::other)?) as usize;
    let (offset, size) = match family {
        2 => (
            mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            mem::size_of::<MIB_UDPROW_OWNER_PID>(),
        ),
        23 => (
            mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            mem::size_of::<MIB_UDP6ROW_OWNER_PID>(),
        ),
        _ => return Err(io::Error::other("Unsupported UDP family")),
    };
    if count > 8192
        || count
            .checked_mul(size)
            .and_then(|n| n.checked_add(offset))
            .is_none_or(|n| n > bytes.len())
    {
        return Err(io::Error::other("UDP row count exceeds buffer or bound"));
    }
    let mut rows = Vec::with_capacity(count);
    for chunk in bytes[offset..offset + count * size].chunks_exact(size) {
        let row = if family == 2 {
            // SAFETY: checked exact native POD row size; unaligned copy has no pointer fields.
            let r = unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<MIB_UDPROW_OWNER_PID>()) };
            ObservedUdpEndpoint {
                pid: r.dwOwningPid,
                process_creation_filetime: None,
                family: "ipv4".into(),
                local_address: Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(),
                local_port: u16::from_be(r.dwLocalPort as u16),
            }
        } else {
            // SAFETY: checked exact native POD row size; unaligned copy has no pointer fields.
            let r = unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<MIB_UDP6ROW_OWNER_PID>()) };
            let ip = Ipv6Addr::from(r.ucLocalAddr);
            let scope = u32::from_be(r.dwLocalScopeId);
            ObservedUdpEndpoint {
                pid: r.dwOwningPid,
                process_creation_filetime: None,
                family: "ipv6".into(),
                local_address: if scope == 0 {
                    ip.to_string()
                } else {
                    format!("{ip}%{scope}")
                },
                local_port: u16::from_be(r.dwLocalPort as u16),
            }
        };
        rows.push(row);
    }
    Ok(rows)
}
pub(crate) fn read(family: u32) -> io::Result<Vec<ObservedUdpEndpoint>> {
    parse(&table(family)?, family)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_udp_snapshot_observes_only_bound_local_fixture() -> io::Result<()> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        assert!(read(2)?.iter().any(|r| r.pid == std::process::id()
            && r.local_port == port
            && r.local_address == "127.0.0.1"));
        Ok(())
    }
    #[test]
    fn udp_decoder_bounds_and_network_order_are_explicit() -> io::Result<()> {
        assert!(parse(&[1, 0, 0], 2).is_err());
        assert!(parse(&[1, 0, 0, 0], 23).is_err());
        assert!(parse(&[0, 0, 0, 0], 99).is_err());
        let mut bytes = Vec::new();
        bytes.extend(1u32.to_ne_bytes());
        bytes.extend(0x0100007fu32.to_ne_bytes());
        bytes.extend(u32::from(1234u16.to_be()).to_ne_bytes());
        bytes.extend(42u32.to_ne_bytes());
        let row = parse(&bytes, 2)?.remove(0);
        assert_eq!(row.local_address, "127.0.0.1");
        assert_eq!(row.local_port, 1234);
        assert_eq!(row.pid, 42);
        assert_eq!(row.process_creation_filetime, None);
        let mut v6 = 1u32.to_ne_bytes().to_vec();
        v6.extend(Ipv6Addr::LOCALHOST.octets());
        v6.extend(7u32.to_be().to_ne_bytes());
        v6.extend(u32::from(5353u16.to_be()).to_ne_bytes());
        v6.extend(42u32.to_ne_bytes());
        let row = parse(&v6, 23)?.remove(0);
        assert_eq!(row.local_address, "::1%7");
        assert_eq!(row.local_port, 5353);
        Ok(())
    }
}
