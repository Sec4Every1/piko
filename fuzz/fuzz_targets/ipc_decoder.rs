#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= piko_ipc::MAX_REQUEST_BYTES {
        let _ = serde_json::from_slice::<piko_ipc::Request>(bytes);
    }
});

