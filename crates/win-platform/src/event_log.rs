//! Thread-affine Windows Event Log handles; XML and bookmarks are owned copies.
use std::{io, marker::PhantomData, ptr, rc::Rc};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, HANDLE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        EventLog::*,
        Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
    },
};

pub const CHANNELS: [&str; 4] = [
    "System",
    "Application",
    "Security",
    "Microsoft-Windows-Windows Defender/Operational",
];
const MAX_RENDER_BYTES: u32 = 128 * 1024;

/// Bounded local Application-log diagnostic, also usable before storage starts.
pub fn report_diagnostic(message: &str, failure: bool) -> io::Result<()> {
    if message.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "diagnostic too large",
        ));
    }
    let source = wide("piko")?;
    let text = wide(message)?;
    // SAFETY: terminated source string; local Event Log source handle uniquely owned.
    let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let strings = [text.as_ptr()];
    // SAFETY: one valid terminated string remains live; no SID or binary payload.
    let ok = unsafe {
        ReportEventW(
            handle,
            if failure {
                EVENTLOG_ERROR_TYPE
            } else {
                EVENTLOG_INFORMATION_TYPE
            },
            0,
            if failure { 1001 } else { 1000 },
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    let error = if ok == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: RegisterEventSource handle is closed exactly once after its last use.
    unsafe {
        DeregisterEventSource(handle);
    }
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

struct EventHandle(EVT_HANDLE, PhantomData<Rc<()>>);
impl EventHandle {
    fn own(handle: EVT_HANDLE) -> io::Result<Self> {
        if handle == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle, PhantomData))
        }
    }
}
impl Drop for EventHandle {
    fn drop(&mut self) {
        // SAFETY: unique successful Evt handle, used and closed on its creating thread.
        unsafe {
            EvtClose(self.0);
        }
    }
}
struct Signal(HANDLE);
impl Drop for Signal {
    fn drop(&mut self) {
        // SAFETY: unique CreateEvent handle; subscription is dropped before signal.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogRecord {
    pub channel: String,
    pub xml: String,
    pub bookmark: String,
}

pub struct Subscription {
    handle: EventHandle,
    bookmark: EventHandle,
    // Fields drop in declaration order, so this outlives the subscription.
    _signal: Signal,
    channel: String,
    initial: std::collections::VecDeque<LogRecord>,
}

fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

fn render(handle: &EventHandle, flag: u32) -> io::Result<String> {
    let (mut bytes, mut properties) = (0, 0);
    // SAFETY: sizing call uses no buffer, live handle and writable DWORD outputs.
    if unsafe {
        EvtRender(
            0,
            handle.0,
            flag,
            0,
            ptr::null_mut(),
            &mut bytes,
            &mut properties,
        )
    } != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected empty Event Log render",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if !(2..=MAX_RENDER_BYTES).contains(&bytes) || bytes % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Event Log XML exceeds 128 KiB UTF-16 limit",
        ));
    }
    let mut buffer = vec![0u16; bytes as usize / 2];
    // SAFETY: u16-aligned writable allocation has exactly the requested byte size;
    // no pointers escape and Windows renders a terminated UTF-16 string.
    if unsafe {
        EvtRender(
            0,
            handle.0,
            flag,
            bytes,
            buffer.as_mut_ptr().cast(),
            &mut bytes,
            &mut properties,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let used = bytes as usize / 2;
    if bytes % 2 != 0 || used == 0 || used > buffer.len() || buffer[used - 1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Event Log render length",
        ));
    }
    String::from_utf16(&buffer[..used - 1])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn next(
    handle: &EventHandle,
    bookmark: &EventHandle,
    channel: &str,
) -> io::Result<Option<LogRecord>> {
    let (mut event, mut returned) = (0, 0);
    // SAFETY: one writable handle slot; nonblocking query, same thread as creator.
    if unsafe { EvtNext(handle.0, 1, &mut event, 0, 0, &mut returned) } == 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(code) if code == ERROR_NO_MORE_ITEMS as i32 || code == ERROR_TIMEOUT as i32)
        {
            Ok(None)
        } else {
            Err(io::Error::new(error.kind(), format!("EvtNext: {error}")))
        };
    }
    let event = EventHandle::own(event)?;
    let xml = render(&event, EvtRenderEventXml)
        .map_err(|e| io::Error::new(e.kind(), format!("EvtRender event: {e}")))?;
    // SAFETY: both handles are owned, valid and on this thread. Bookmark stores a
    // position only; durable advancement occurs when caller commits the record.
    if unsafe { EvtUpdateBookmark(bookmark.0, event.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(LogRecord {
        channel: channel.into(),
        xml,
        bookmark: render(bookmark, EvtRenderBookmark)?,
    }))
}

impl Subscription {
    pub fn open(channel: &str, saved_bookmark: Option<&str>) -> io::Result<Self> {
        if saved_bookmark.is_some_and(|value| value.len() > 8192) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bookmark exceeds 8 KiB",
            ));
        }
        if !CHANNELS.contains(&channel) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported channel",
            ));
        }
        let path = wide(channel)?;
        let mut initial = std::collections::VecDeque::new();
        if saved_bookmark.is_none() {
            // SAFETY: local query; terminated path, wildcard query, no borrowed output.
            let query = EventHandle::own(unsafe {
                EvtQuery(
                    0,
                    path.as_ptr(),
                    ptr::null(),
                    EvtQueryChannelPath | EvtQueryReverseDirection,
                )
            })?;
            // SAFETY: null creates an empty bookmark owned by this scope.
            let scratch = EventHandle::own(unsafe { EvtCreateBookmark(ptr::null()) })?;
            for _ in 0..16 {
                match next(&query, &scratch, channel)? {
                    Some(record) => initial.push_front(record),
                    None => break,
                }
            }
        }
        let resume =
            saved_bookmark.or_else(|| initial.back().map(|record| record.bookmark.as_str()));
        let bookmark_xml = resume.map(wide).transpose()?;
        // SAFETY: optional terminated XML lives for call; result is separately owned.
        let bookmark = EventHandle::own(unsafe {
            EvtCreateBookmark(bookmark_xml.as_ref().map_or(ptr::null(), |b| b.as_ptr()))
        })?;
        // SAFETY: unnamed local signal, no inheritance, unique owned handle.
        let signal = unsafe { CreateEventW(ptr::null(), 1, 1, ptr::null()) };
        if signal.is_null() {
            return Err(io::Error::last_os_error());
        }
        let signal = Signal(signal);
        let flags = if resume.is_some() {
            EvtSubscribeStartAfterBookmark | EvtSubscribeStrict
        } else {
            EvtSubscribeStartAtOldestRecord | EvtSubscribeStrict
        };
        // SAFETY: pull subscription (no callback); all input handles and strings live
        // through creation; signal outlives returned handle. No foreign callback state.
        let handle = EventHandle::own(unsafe {
            EvtSubscribe(
                0,
                signal.0,
                path.as_ptr(),
                ptr::null(),
                if resume.is_some() { bookmark.0 } else { 0 },
                ptr::null(),
                None,
                flags,
            )
        })?;
        Ok(Self {
            handle,
            bookmark,
            _signal: signal,
            channel: channel.into(),
            initial,
        })
    }

    pub fn poll(&mut self) -> io::Result<Option<LogRecord>> {
        if let Some(record) = self.initial.pop_front() {
            return Ok(Some(record));
        }
        // SAFETY: live manual-reset signal; zero timeout never blocks the collector.
        match unsafe { WaitForSingleObject(self._signal.0, 0) } {
            WAIT_TIMEOUT => return Ok(None),
            WAIT_OBJECT_0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        let record = next(&self.handle, &self.bookmark, &self.channel)?;
        if record.is_none() {
            // SAFETY: live uniquely owned event; reset after enumerating all results.
            if unsafe { ResetEvent(self._signal.0) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsupported_channel_and_unbounded_bookmark_before_native_call() {
        assert!(Subscription::open("System\0Security", None).is_err());
        assert!(Subscription::open("System", Some(&"x".repeat(8193))).is_err());
        assert!(report_diagnostic(&"x".repeat(4097), false).is_err());
    }
}
