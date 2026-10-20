//! Owned, bounded real-time manifest ETW session. No driver, audit policy, token
//! privilege adjustment, or existing trace session is touched. A standard token
//! may fail StartTrace/EnableTrace/OpenTrace: callers must show that degradation.
use std::{
    io, mem, ptr,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{
            ERROR_CANCELLED, ERROR_CTX_CLOSE_PENDING, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
        },
        System::Diagnostics::Etw::*,
    },
};

pub const PROVIDER_ID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const QUEUE_CAPACITY: usize = 32;
const MAX_METADATA_BYTES: usize = 256 * 1024;
const MAX_PROPERTIES: usize = 128;
const PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EtwFields {
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub creation_filetime: Option<u64>,
    pub image_name: Option<String>,
    /// Windows/Terminal Services session, never an authentication/logon LUID.
    pub session_id: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedData {
    pub kind: u16,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtwRecord {
    pub provider_id: String,
    pub event_id: u16,
    pub version: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
    pub level: u8,
    pub flags: u16,
    pub header_process_id: u32,
    pub header_thread_id: u32,
    pub activity_id: String,
    /// ProcessTrace converts QPC timestamps to FILETIME; raw timestamp mode is off.
    pub timestamp_filetime: u64,
    pub observed_at_unix_ms: i64,
    pub payload: Vec<u8>,
    pub extended_data: Vec<ExtendedData>,
    pub fields: EtwFields,
    /// Raw evidence survives TDH/schema failures; fields remain unknown.
    pub decode_error: Option<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EtwStatistics {
    pub received: u64,
    pub queue_dropped: u64,
    pub malformed: u64,
    pub decode_failures: u64,
    pub events_lost: u32,
    pub real_time_buffers_lost: u32,
    pub last_seen_unix_ms: Option<i64>,
    pub running: bool,
    pub processing_error: Option<u32>,
}
#[derive(Default)]
struct Shared {
    stop: AtomicBool,
    received: AtomicU64,
    dropped: AtomicU64,
    malformed: AtomicU64,
    decode_failures: AtomicU64,
    last_seen: AtomicI64,
    running: AtomicBool,
    processing_error: AtomicU32,
    consumer: Mutex<Option<u64>>,
}
struct Context {
    sender: mpsc::SyncSender<EtwRecord>,
    shared: Arc<Shared>,
}
#[repr(C)]
struct Properties {
    value: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
}
impl Properties {
    fn new(name: &[u16], id: GUID) -> io::Result<Box<Self>> {
        if name.is_empty() || name.len() > 128 || name.last() != Some(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ETW session name exceeds bound",
            ));
        }
        let mut result = Box::new(Self {
            value: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 128],
        });
        result.name[..name.len()].copy_from_slice(name);
        result.value.Wnode.BufferSize = mem::size_of::<Self>() as u32;
        result.value.Wnode.Guid = id;
        result.value.Wnode.ClientContext = 1; // QPC; converted by ProcessTrace.
        result.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        result.value.BufferSize = 64; // KiB, independent of CPU count.
        result.value.MinimumBuffers = 2;
        result.value.MaximumBuffers = 8;
        result.value.LogFileMode =
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        result.value.FlushTimer = 1;
        result.value.LoggerNameOffset = mem::offset_of!(Self, name) as u32;
        Ok(result)
    }
}

/// Controller owns only the session created by this call. OpenTrace/ProcessTrace
/// live on a dedicated thread, and its Box<Context> outlives every OS callback.
pub struct EtwSession {
    handle: CONTROLTRACE_HANDLE,
    id: GUID,
    name: Vec<u16>,
    receiver: mpsc::Receiver<EtwRecord>,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    done: mpsc::Receiver<()>,
    stopped: bool,
}
impl EtwSession {
    pub fn start() -> io::Result<Self> {
        let uuid = Uuid::new_v4();
        let id = GUID::from_u128(uuid.as_u128());
        let name: Vec<u16> = format!("Piko.ProcessImage.{}.{uuid}", std::process::id())
            .encode_utf16()
            .chain([0])
            .collect();
        let mut properties = Properties::new(&name, id)?;
        let mut handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: aligned owned structure followed by logger name, writable until return.
        check(unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut properties.value) })
            .map_err(|error| io::Error::new(error.kind(), format!("ETW StartTrace: {error}")))?;
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (ready_sender, ready) = mpsc::sync_channel(1);
        let (done_sender, done) = mpsc::channel();
        let shared = Arc::new(Shared::default());
        let mut session = Self {
            handle,
            id,
            name,
            receiver,
            shared: shared.clone(),
            worker: None,
            done,
            stopped: false,
        };
        // Event-ID filter excludes thread/rundown/priority/job events at the source.
        #[repr(C)]
        struct IdFilter {
            include: bool,
            reserved: u8,
            count: u16,
            events: [u16; 3],
        }
        let filter = IdFilter {
            include: true,
            reserved: 0,
            count: 3,
            events: [1, 2, 5],
        };
        let mut descriptor = EVENT_FILTER_DESCRIPTOR {
            Ptr: (&filter as *const IdFilter) as u64,
            Size: mem::size_of::<IdFilter>() as u32,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        };
        let parameters = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableFilterDesc: &mut descriptor,
            FilterDescCount: 1,
            ..Default::default()
        };
        // SAFETY: stack filter/descriptor/parameters all live through synchronous enable.
        check(unsafe {
            EnableTraceEx2(
                handle,
                &PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION as u8,
                0x10 | 0x40,
                0,
                1000,
                &parameters,
            )
        })
        .map_err(|error| io::Error::new(error.kind(), format!("ETW EnableTraceEx2: {error}")))?;
        let mut worker_name = session.name.clone();
        session.worker = Some(
            thread::Builder::new()
                .name("piko-etw-native".into())
                .spawn(move || {
                    let mut context = Box::new(Context {
                        sender,
                        shared: shared.clone(),
                    });
                    let mut logfile = EVENT_TRACE_LOGFILEW {
                        LoggerName: worker_name.as_mut_ptr(),
                        Context: (&mut *context as *mut Context).cast(),
                        BufferCallback: Some(buffer_callback),
                        ..Default::default()
                    };
                    logfile.Anonymous1.ProcessTraceMode =
                        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                    logfile.Anonymous2.EventRecordCallback = Some(record_callback);
                    // SAFETY: owned name and Context remain stable throughout OpenTrace/ProcessTrace.
                    let trace = unsafe { OpenTraceW(&mut logfile) };
                    if trace.Value == u64::MAX {
                        let _ = ready_sender.send(Err(io::Error::last_os_error()));
                        let _ = done_sender.send(());
                        return;
                    }
                    if let Ok(mut slot) = shared.consumer.lock() {
                        *slot = Some(trace.Value);
                    }
                    shared.running.store(true, Ordering::Release);
                    let _ = ready_sender.send(Ok(()));
                    // SAFETY: OpenTrace handle and callback context are live on this thread.
                    let status = unsafe { ProcessTrace(&trace, 1, ptr::null(), ptr::null()) };
                    if status != ERROR_SUCCESS && status != ERROR_CANCELLED {
                        shared.processing_error.store(status, Ordering::Release);
                    }
                    shared.running.store(false, Ordering::Release);
                    // Controller and worker serialize CloseTrace: handle is closed exactly once.
                    close_consumer(&shared);
                    drop(context); // ProcessTrace returned; no callback may borrow this context now.
                    let _ = done_sender.send(());
                })?,
        );
        match ready.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => result?,
            Err(error) => return Err(io::Error::other(format!("ETW consumer startup: {error}"))),
        }
        Ok(session)
    }
    pub fn poll(&self, timeout: Duration) -> io::Result<Option<EtwRecord>> {
        match self.receiver.recv_timeout(timeout) {
            Ok(record) => Ok(Some(record)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ETW consumer stopped",
            )),
        }
    }
    pub fn statistics(&self) -> io::Result<EtwStatistics> {
        let mut properties = Properties::new(&self.name, self.id)?;
        // SAFETY: queries only our successfully created session; independent bounded buffer.
        check(unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                &mut properties.value,
                EVENT_TRACE_CONTROL_QUERY,
            )
        })?;
        if !same_guid(properties.value.Wnode.Guid, self.id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ETW session identity changed",
            ));
        }
        let last_seen = self.shared.last_seen.load(Ordering::Acquire);
        let error = self.shared.processing_error.load(Ordering::Acquire);
        Ok(EtwStatistics {
            received: self.shared.received.load(Ordering::Relaxed),
            queue_dropped: self.shared.dropped.load(Ordering::Relaxed),
            malformed: self.shared.malformed.load(Ordering::Relaxed),
            decode_failures: self.shared.decode_failures.load(Ordering::Relaxed),
            events_lost: properties.value.EventsLost,
            real_time_buffers_lost: properties.value.RealTimeBuffersLost,
            last_seen_unix_ms: (last_seen > 0).then_some(last_seen),
            running: self.shared.running.load(Ordering::Acquire),
            processing_error: (error != 0).then_some(error),
        })
    }
    pub fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        self.shared.stop.store(true, Ordering::Release);
        let mut properties = Properties::new(&self.name, self.id)?;
        // SAFETY: query only this controller's successfully created session.
        let query = unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                &mut properties.value,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        let result = if query != ERROR_SUCCESS {
            check(query)
        } else if !same_guid(properties.value.Wnode.Guid, self.id) {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ETW cleanup refused: session identity changed",
            ))
        } else {
            // SAFETY: only our session, with its original GUID verified immediately above.
            check(unsafe {
                ControlTraceW(
                    self.handle,
                    self.name.as_ptr(),
                    &mut properties.value,
                    EVENT_TRACE_CONTROL_STOP,
                )
            })
        };
        close_consumer(&self.shared);
        // CloseTrace may return CLOSE_PENDING. The worker keeps context alive until return.
        // A slow Windows callback never frees its context early or blocks shutdown indefinitely.
        if self.worker.is_some() && self.done.recv_timeout(Duration::from_secs(5)).is_ok() {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
        result
    }
}
impl Drop for EtwSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
fn close_consumer(shared: &Shared) {
    if let Ok(mut slot) = shared.consumer.lock() {
        if let Some(value) = slot.take() {
            // SAFETY: unique OpenTrace handle, consumed once under mutex; valid cross-thread for realtime.
            let status = unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: value }) };
            if status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING {
                shared.processing_error.store(status, Ordering::Release);
            }
        }
    }
}
fn check(status: u32) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn guid_text(value: GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7]
    )
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

unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    // SAFETY: Windows provides this logfile and our Context for the callback duration.
    let context = unsafe { (*logfile).Context.cast::<Context>().as_ref() };
    context.map_or(0, |c| u32::from(!c.shared.stop.load(Ordering::Acquire)))
}
unsafe extern "system" fn record_callback(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }
    // SAFETY: OS EVENT_RECORD and our stable Context valid until this callback returns.
    let Some(context) = (unsafe { (*event).UserContext.cast::<Context>().as_ref() }) else {
        return;
    };
    if context.shared.stop.load(Ordering::Acquire) {
        return;
    }
    // No panic is allowed to unwind into Windows. Raw pointers never leave this module.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: native record is copied before callback completion.
        unsafe { copy_record(&*event) }
    }));
    match result {
        Ok(Ok(Some(record))) => {
            context.shared.received.fetch_add(1, Ordering::Relaxed);
            context
                .shared
                .last_seen
                .store(record.observed_at_unix_ms, Ordering::Release);
            if record.decode_error.is_some() {
                context
                    .shared
                    .decode_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            if context.sender.try_send(record).is_err() {
                context.shared.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(Ok(None)) => {}
        _ => {
            context.shared.malformed.fetch_add(1, Ordering::Relaxed);
        }
    }
}
unsafe fn copy_record(event: &EVENT_RECORD) -> io::Result<Option<EtwRecord>> {
    if !same_guid(event.EventHeader.ProviderId, PROVIDER)
        || !matches!(event.EventHeader.EventDescriptor.Id, 1 | 2 | 5 | 6)
    {
        return Ok(None);
    }
    if event.ExtendedDataCount > 32
        || (event.UserDataLength > 0 && event.UserData.is_null())
        || (event.ExtendedDataCount > 0 && event.ExtendedData.is_null())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW payload pointers/count",
        ));
    }
    let payload = if event.UserDataLength == 0 {
        Vec::new()
    } else {
        // SAFETY: OS owns UserDataLength bytes until callback returns; copied immediately.
        unsafe {
            std::slice::from_raw_parts(
                event.UserData.cast::<u8>(),
                usize::from(event.UserDataLength),
            )
        }
        .to_vec()
    };
    let mut total = payload.len();
    let mut extended_data = Vec::new();
    for index in 0..usize::from(event.ExtendedDataCount) {
        // SAFETY: native ExtendedData array contains ExtendedDataCount elements.
        let item = unsafe { &*event.ExtendedData.add(index) };
        total = total
            .checked_add(usize::from(item.DataSize))
            .ok_or_else(|| io::Error::other("ETW record size overflow"))?;
        if total > MAX_RECORD_BYTES || (item.DataSize > 0 && item.DataPtr == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ETW raw record exceeds 64 KiB bound",
            ));
        }
        let bytes = if item.DataSize == 0 {
            Vec::new()
        } else {
            // SAFETY: ETW-provided extended-data pointer valid for DataSize within callback.
            unsafe {
                std::slice::from_raw_parts(item.DataPtr as *const u8, usize::from(item.DataSize))
            }
            .to_vec()
        };
        extended_data.push(ExtendedData {
            kind: item.ExtType,
            bytes,
        });
    }
    let (fields, decode_error) = match decode_fields(event) {
        Ok(fields) => (fields, None),
        Err(error) => (EtwFields::default(), Some(error.to_string())),
    };
    let d = event.EventHeader.EventDescriptor;
    Ok(Some(EtwRecord {
        provider_id: PROVIDER_ID.into(),
        event_id: d.Id,
        version: d.Version,
        opcode: d.Opcode,
        task: d.Task,
        keyword: d.Keyword,
        level: d.Level,
        flags: event.EventHeader.Flags,
        header_process_id: event.EventHeader.ProcessId,
        header_thread_id: event.EventHeader.ThreadId,
        activity_id: guid_text(event.EventHeader.ActivityId),
        timestamp_filetime: u64::try_from(event.EventHeader.TimeStamp).map_err(io::Error::other)?,
        observed_at_unix_ms: now()?,
        payload,
        extended_data,
        fields,
        decode_error,
    }))
}

fn metadata_string(bytes: &[u8], offset: u32) -> io::Result<String> {
    let offset = offset as usize;
    if offset < mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
        || !offset.is_multiple_of(2)
        || offset >= bytes.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TDH property name offset",
        ));
    }
    let mut units = Vec::new();
    let (chunks, _) = bytes[offset..].as_chunks::<2>();
    for chunk in chunks.iter().take(129) {
        let unit = u16::from_le_bytes(*chunk);
        if unit == 0 {
            return String::from_utf16(&units).map_err(io::Error::other);
        }
        units.push(unit);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unterminated TDH property name",
    ))
}
fn decode_fields(event: &EVENT_RECORD) -> io::Result<EtwFields> {
    let mut size = 0u32;
    // SAFETY: callback event live; sizing call writes only size and no buffer.
    let status =
        unsafe { TdhGetEventInformation(event, 0, ptr::null(), ptr::null_mut(), &mut size) };
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if (size as usize) < mem::size_of::<TRACE_EVENT_INFO>() || size as usize > MAX_METADATA_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TDH metadata outside bound",
        ));
    }
    // usize alignment covers TRACE_EVENT_INFO; byte length is still bounded before allocation.
    let mut memory = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
    let capacity = memory.len() * mem::size_of::<usize>();
    // SAFETY: aligned buffer capacity >= requested size, event live during TDH call.
    check(unsafe {
        TdhGetEventInformation(event, 0, ptr::null(), memory.as_mut_ptr().cast(), &mut size)
    })?;
    if size as usize > capacity || (size as usize) < mem::size_of::<TRACE_EVENT_INFO>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TDH returned invalid size",
        ));
    }
    // SAFETY: successful TDH filled aligned metadata structure and bounded bytes.
    let info = unsafe { &*memory.as_ptr().cast::<TRACE_EVENT_INFO>() };
    let count = info.TopLevelPropertyCount as usize;
    let start = mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    if info.DecodingSource != DecodingSourceXMLFile
        || !same_guid(info.ProviderGuid, PROVIDER)
        || count > MAX_PROPERTIES
        || count > info.PropertyCount as usize
        || start + info.PropertyCount as usize * mem::size_of::<EVENT_PROPERTY_INFO>()
            > size as usize
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported or malformed ETW metadata",
        ));
    }
    // SAFETY: successful native buffer has size valid bytes; used only to bound offsets.
    let bytes = unsafe { std::slice::from_raw_parts(memory.as_ptr().cast::<u8>(), size as usize) };
    let mut fields = EtwFields::default();
    let mut seen = std::collections::HashSet::new();
    for index in 0..count {
        // SAFETY: full property array size was validated; base aligned by TDH ABI.
        let property = unsafe {
            &*memory
                .as_ptr()
                .cast::<u8>()
                .add(start)
                .cast::<EVENT_PROPERTY_INFO>()
                .add(index)
        };
        let name = metadata_string(bytes, property.NameOffset)?;
        if !matches!(
            name.as_str(),
            "ProcessID" | "ParentProcessID" | "CreateTime" | "ImageName" | "SessionID"
        ) {
            continue;
        }
        if !seen.insert(name.clone())
            || property.Flags & (PropertyStruct | PropertyParamCount | PropertyHasCustomSchema) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ambiguous or composite ETW field",
            ));
        }
        // SAFETY: structure/custom/count flags excluded; union represents scalar metadata.
        let input = unsafe { property.Anonymous1.nonStructType.InType } as i32;
        // SAFETY: ParamCount excluded, therefore literal count active.
        if unsafe { property.Anonymous2.count } != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ETW field is an array",
            ));
        }
        let expected = match name.as_str() {
            "CreateTime" => TDH_INTYPE_FILETIME,
            "ImageName" => TDH_INTYPE_UNICODESTRING,
            _ => TDH_INTYPE_UINT32,
        };
        if input != expected && !(name == "ImageName" && input == TDH_INTYPE_ANSISTRING) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ETW field type changed",
            ));
        }
        let value = get_property(event, &name)?;
        match name.as_str() {
            "ProcessID" => fields.process_id = Some(parse_u32(&value)?),
            "ParentProcessID" => fields.parent_process_id = Some(parse_u32(&value)?),
            "SessionID" => fields.session_id = Some(parse_u32(&value)?),
            "CreateTime" => {
                fields.creation_filetime =
                    Some(u64::from_le_bytes(value.as_slice().try_into().map_err(
                        |_| io::Error::new(io::ErrorKind::InvalidData, "invalid FILETIME length"),
                    )?))
            }
            "ImageName" if input == TDH_INTYPE_ANSISTRING => {
                fields.image_name = parse_ansi(&value)?
            }
            "ImageName" => fields.image_name = Some(parse_unicode(&value)?),
            _ => {}
        }
    }
    if fields.process_id.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ETW payload ProcessID missing",
        ));
    }
    Ok(fields)
}
fn get_property(event: &EVENT_RECORD, name: &str) -> io::Result<Vec<u8>> {
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0u32;
    // SAFETY: native event and UTF16 descriptor name live; OS writes only size.
    check(unsafe { TdhGetPropertySize(event, 0, ptr::null(), 1, &descriptor, &mut size) })?;
    if size == 0 || size > 8192 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ETW field exceeds 8 KiB bound",
        ));
    }
    let mut bytes = vec![0u8; size as usize];
    // SAFETY: descriptor unchanged and writable buffer exactly property size.
    check(unsafe {
        TdhGetProperty(
            event,
            0,
            ptr::null(),
            1,
            &descriptor,
            size,
            bytes.as_mut_ptr(),
        )
    })?;
    Ok(bytes)
}
fn parse_u32(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid UINT32 length")
    })?))
}
fn parse_unicode(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() < 2 || bytes.len() > 8192 || !bytes.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW Unicode length",
        ));
    }
    let (chunks, _) = bytes.as_chunks::<2>();
    let units: Vec<_> = chunks
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW Unicode terminator",
        ));
    }
    let value = String::from_utf16(&units[..units.len() - 1]).map_err(io::Error::other)?;
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW Unicode text",
        ));
    }
    Ok(value)
}

fn parse_ansi(bytes: &[u8]) -> io::Result<Option<String>> {
    if bytes.is_empty()
        || bytes.len() > 4096
        || bytes.last() != Some(&0)
        || bytes[..bytes.len() - 1].contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW ANSI string",
        ));
    }
    let value = &bytes[..bytes.len() - 1];
    // The kernel ProcessStop schema uses ANSI ImageName; no source codepage is
    // supplied. Preserve bytes and leave a non-ASCII name unknown rather than
    // decode it using the consumer's potentially different locale.
    if !value.is_ascii() {
        return Ok(None);
    }
    if value.iter().any(u8::is_ascii_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETW ANSI control character",
        ));
    }
    String::from_utf8(value.to_vec())
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strings_and_scalars_reject_ambiguous_or_unbounded_payloads() -> io::Result<()> {
        let bytes: Vec<_> = "C:\\app\\example.exe"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(parse_unicode(&bytes)?, "C:\\app\\example.exe");
        assert!(parse_unicode(&[b'a', 0]).is_err());
        assert!(parse_unicode(&[0, 0, b'a', 0, 0, 0]).is_err());
        assert!(parse_unicode(&[0, 0xd8, 0, 0]).is_err());
        assert!(parse_unicode(&vec![0; 8194]).is_err());
        assert_eq!(parse_u32(&42u32.to_le_bytes())?, 42);
        assert!(parse_u32(&[1, 2, 3]).is_err());
        assert_eq!(
            parse_ansi(b"example.exe\0")?.as_deref(),
            Some("example.exe")
        );
        assert_eq!(parse_ansi(&[0xe9, 0])?, None);
        assert!(parse_ansi(b"example.exe").is_err());
        Ok(())
    }
    #[test]
    fn properties_budget_is_fixed_and_does_not_use_system_logger() -> io::Result<()> {
        let name: Vec<_> = "Piko.Test".encode_utf16().chain([0]).collect();
        let p = Properties::new(&name, PROVIDER)?;
        assert_eq!(p.value.MaximumBuffers * p.value.BufferSize, 512);
        assert_eq!(p.value.EnableFlags, 0);
        assert_eq!(p.value.LogFileNameOffset, 0);
        assert_eq!(p.value.LogFileMode & EVENT_TRACE_SYSTEM_LOGGER_MODE, 0);
        assert!(Properties::new(&[1; 129], PROVIDER).is_err());
        Ok(())
    }
    #[test]
    fn native_record_rejects_bad_pointer_bounds_before_copying() -> io::Result<()> {
        let mut event = EVENT_RECORD::default();
        event.EventHeader.ProviderId = PROVIDER;
        event.EventHeader.EventDescriptor.Id = 1;
        event.UserDataLength = 4;
        // SAFETY: fixture record owned here; malformed pointer rejected before dereference.
        assert!(unsafe { copy_record(&event) }.is_err());
        event.UserDataLength = 0;
        event.ExtendedDataCount = 33;
        // SAFETY: fixture record owned here; excessive count rejected before dereference.
        assert!(unsafe { copy_record(&event) }.is_err());
        event.EventHeader.ProviderId = GUID::default();
        // SAFETY: fixture record owned here; unselected provider ignored before any payload access.
        assert!(unsafe { copy_record(&event) }?.is_none());
        Ok(())
    }
    #[test]
    fn installed_tdh_manifest_decodes_version_zero_start_fixture() -> io::Result<()> {
        let mut payload = Vec::new();
        payload.extend(42u32.to_le_bytes());
        payload.extend(133_000_000_000_000_001u64.to_le_bytes());
        payload.extend(7u32.to_le_bytes());
        payload.extend(2u32.to_le_bytes());
        payload.extend(
            "C:\\app\\example.exe"
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes),
        );
        let mut event = EVENT_RECORD::default();
        event.EventHeader.ProviderId = PROVIDER;
        event.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;
        event.EventHeader.EventDescriptor = EVENT_DESCRIPTOR {
            Id: 1,
            Version: 0,
            Channel: 16,
            Level: 4,
            Opcode: 1,
            Task: 1,
            Keyword: 0x8000_0000_0000_0010,
        };
        event.UserDataLength = payload.len() as u16;
        event.UserData = payload.as_mut_ptr().cast();
        let fields = decode_fields(&event)?;
        assert_eq!(fields.process_id, Some(42));
        assert_eq!(fields.parent_process_id, Some(7));
        assert_eq!(fields.creation_filetime, Some(133_000_000_000_000_001));
        assert_eq!(fields.image_name.as_deref(), Some("C:\\app\\example.exe"));
        Ok(())
    }
    fn fixture_fields(id: u16, version: u8, payload: &mut [u8]) -> io::Result<EtwFields> {
        let mut event = EVENT_RECORD::default();
        event.EventHeader.ProviderId = PROVIDER;
        event.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;
        event.EventHeader.EventDescriptor = EVENT_DESCRIPTOR {
            Id: id,
            Version: version,
            Channel: 16,
            Level: 4,
            Opcode: if id == 1 {
                1
            } else if id == 2 {
                2
            } else {
                0
            },
            Task: id,
            Keyword: if id <= 2 {
                0x8000_0000_0000_0010
            } else {
                0x8000_0000_0000_0040
            },
        };
        event.UserDataLength = payload.len() as u16;
        event.UserData = payload.as_mut_ptr().cast();
        decode_fields(&event)
    }
    fn unicode_bytes(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    #[test]
    fn installed_tdh_manifest_decodes_current_start_stop_and_image_fixtures() -> io::Result<()> {
        let creation = 133_000_000_000_000_001u64;
        let mut start = Vec::new();
        start.extend(42u32.to_le_bytes());
        start.extend(100u64.to_le_bytes());
        start.extend(creation.to_le_bytes());
        start.extend(7u32.to_le_bytes());
        start.extend(90u64.to_le_bytes());
        for value in [2u32, 0, 1, 0] {
            start.extend(value.to_le_bytes());
        }
        start.extend([1, 1, 0, 0, 0, 0, 0, 16]); // SID S-1-16-8192.
        start.extend(8192u32.to_le_bytes());
        start.extend(unicode_bytes("C:\\app\\example.exe"));
        start.extend([0; 8]); // ImageChecksum/TimeDateStamp.
        start.extend(unicode_bytes(""));
        start.extend(unicode_bytes(""));
        start.extend(0u32.to_le_bytes());
        let fields = fixture_fields(1, 4, &mut start)?;
        assert_eq!(fields.process_id, Some(42));
        assert_eq!(fields.parent_process_id, Some(7));
        assert_eq!(fields.creation_filetime, Some(creation));
        assert_eq!(fields.image_name.as_deref(), Some("C:\\app\\example.exe"));

        let mut stop = Vec::new();
        stop.extend(42u32.to_le_bytes());
        stop.extend(100u64.to_le_bytes());
        stop.extend(creation.to_le_bytes());
        stop.extend((creation + 10_000).to_le_bytes());
        stop.extend([0; 12]); // ExitCode, TokenElevationType, HandleCount.
        stop.extend([0; 24]); // CommitCharge, CommitPeak, CPUCycleCount.
        stop.extend([0; 20]); // Read/Write operation and transfer counts, HardFaultCount.
        stop.extend(b"example.exe\0");
        let fields = fixture_fields(2, 2, &mut stop)?;
        assert_eq!(fields.process_id, Some(42));
        assert_eq!(fields.creation_filetime, Some(creation));
        assert_eq!(fields.image_name.as_deref(), Some("example.exe"));
        assert_eq!(fields.parent_process_id, None);
        for id in [5, 6] {
            let mut image = Vec::new();
            image.extend(0x100000u64.to_le_bytes());
            image.extend(4096u64.to_le_bytes());
            image.extend(42u32.to_le_bytes());
            image.extend([0; 8]);
            image.extend(0x100000u64.to_le_bytes());
            image.extend(unicode_bytes("C:\\app\\module.dll"));
            let fields = fixture_fields(id, 0, &mut image)?;
            assert_eq!(fields.process_id, Some(42));
            assert_eq!(fields.creation_filetime, None);
            assert_eq!(fields.image_name.as_deref(), Some("C:\\app\\module.dll"));
        }
        Ok(())
    }
    #[test]
    fn callback_queue_saturation_is_counted_and_raw_is_retained() -> io::Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let shared = Arc::new(Shared::default());
        let mut context = Context {
            sender,
            shared: shared.clone(),
        };
        let mut event = EVENT_RECORD::default();
        event.EventHeader.ProviderId = PROVIDER;
        event.EventHeader.TimeStamp = 133_000_000_000_000_001;
        event.EventHeader.EventDescriptor.Id = 1;
        event.EventHeader.EventDescriptor.Version = 255; // Unavailable schema: raw only.
        event.UserContext = (&mut context as *mut Context).cast();
        // SAFETY: fixture event/context remain owned and alive through both callbacks.
        unsafe {
            record_callback(&mut event);
            record_callback(&mut event);
        }
        assert_eq!(shared.received.load(Ordering::Relaxed), 2);
        assert_eq!(shared.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(shared.decode_failures.load(Ordering::Relaxed), 2);
        let record = receiver
            .recv_timeout(Duration::from_millis(100))
            .map_err(io::Error::other)?;
        assert_eq!(record.version, 255);
        assert!(record.decode_error.is_some());
        assert_eq!(record.fields.process_id, None);
        Ok(())
    }
    #[test]
    #[ignore = "explicit local ETW permission/capture probe; never changes token or account policy"]
    fn native_permission_or_child_process_capture_probe() -> io::Result<()> {
        use std::os::windows::process::CommandExt;
        let mut session = match EtwSession::start() {
            Ok(session) => session,
            Err(error) if matches!(error.raw_os_error(), Some(5 | 1314)) => {
                println!("ETW unavailable under this token: {error}; capture not qualified");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .arg("--list")
            .creation_flags(0x08000000)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let pid = child.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut observed = false;
        while std::time::Instant::now() < deadline {
            if let Some(record) = session.poll(Duration::from_millis(200))? {
                if record.event_id == 1 && record.fields.process_id == Some(pid) {
                    println!("Native child start captured via TDH: PID {pid}, version {}, creation {:?}, image {:?}", record.version, record.fields.creation_filetime, record.fields.image_name);
                    assert!(record.decode_error.is_none());
                    assert!(record.fields.creation_filetime.is_some());
                    assert!(record.fields.image_name.is_some());
                    observed = true;
                    break;
                }
            }
        }
        let _ = child.wait()?;
        let statistics = session.statistics()?;
        println!("Native ETW statistics: {statistics:?}");
        session.stop()?;
        assert!(
            observed,
            "native child process start not captured/decoded; no qualification"
        );
        Ok(())
    }
}
