#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        runtime::bash_validation::classify_command(s);
        runtime::bash_validation::classify_detailed(s);
        runtime::bash_validation::check_destructive(s);
    }
});
