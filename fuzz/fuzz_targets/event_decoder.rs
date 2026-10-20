#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(event) = piko_event_schema::SecurityEvent::decode(bytes) {
        if let Ok(encoded) = serde_json::to_vec(&event) {
            assert!(piko_event_schema::SecurityEvent::decode(&encoded).is_ok());
        }
    }
});

