//! Read-only resource counters for the calling process; no enumeration or elevation.
use std::io;
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::{
        ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        },
        Threading::{GetCurrentProcess, GetProcessTimes},
    },
};
#[derive(Clone, Copy)]
pub struct Counters {
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub cpu_ticks: u64,
}
pub fn current_process() -> io::Result<Counters> {
    // SAFETY: process pseudo-handle is borrowed and must never be closed.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: native counter structure contains only integers; zero is valid initialization.
    let mut memory: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    memory.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    // SAFETY: documented EX layout extends the base structure; full size and live writable buffer.
    if unsafe {
        K32GetProcessMemoryInfo(
            process,
            (&mut memory as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            memory.cb,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: live pseudo-handle; four distinct writable FILETIME buffers.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let ticks = |v: FILETIME| (u64::from(v.dwHighDateTime) << 32) | u64::from(v.dwLowDateTime);
    Ok(Counters {
        working_set_bytes: memory.WorkingSetSize as u64,
        private_bytes: memory.PrivateUsage as u64,
        cpu_ticks: ticks(kernel)
            .checked_add(ticks(user))
            .ok_or_else(|| io::Error::other("CPU counter overflow"))?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_process_counters_are_native_and_cpu_is_monotonic() -> io::Result<()> {
        let a = current_process()?;
        let b = current_process()?;
        assert!(a.working_set_bytes > 0 && a.private_bytes > 0);
        assert!(b.cpu_ticks >= a.cpu_ticks);
        Ok(())
    }
}
