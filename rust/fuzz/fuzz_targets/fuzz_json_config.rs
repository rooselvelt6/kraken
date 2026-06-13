#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON deserialization of arbitrary bytes
    // This tests that serde_json doesn't panic on malformed input
    let _: Result<serde_json::Value, _> = serde_json::from_slice(data);
    // Also test raw string parsing
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<serde_json::Value, _> = serde_json::from_str(s);
    }
});
