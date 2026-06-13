#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Test on a dummy workspace root — should not panic
        let _ = runtime::path_traversal::validate_path_safety(
            std::path::Path::new(s),
            std::path::Path::new("/tmp/workspace"),
        );
    }
});
