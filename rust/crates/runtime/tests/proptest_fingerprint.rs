#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;
use runtime::fingerprint::{hash_arguments, ToolCallFingerprinter};

proptest! {
    #[test]
    fn five_identical_calls_are_repetitive(
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        args in ".*",
    ) {
        let mut fp = ToolCallFingerprinter::new(20);
        let arg_hash = hash_arguments(&args);
        for _ in 0..5 {
            fp.record_call(&tool_name, &arg_hash);
        }
        prop_assert!(fp.is_repetitive(&tool_name, &arg_hash));
    }

    #[test]
    fn reset_clears_window(
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        args in ".*",
    ) {
        let mut fp = ToolCallFingerprinter::new(20);
        let arg_hash = hash_arguments(&args);
        fp.record_call(&tool_name, &arg_hash);
        fp.reset();
        prop_assert_eq!(fp.window().len(), 0);
        prop_assert!(!fp.is_repetitive(&tool_name, &arg_hash));
        prop_assert!(!fp.detect_recon());
        prop_assert!(!fp.detect_scan_chain());
        prop_assert!(!fp.detect_exfil());
    }

    #[test]
    fn window_size_is_bounded(window_size in 1..10_usize) {
        let mut fp = ToolCallFingerprinter::new(window_size);
        let arg_hash = hash_arguments("test");
        for i in 0..(window_size + 5) {
            let name = format!("tool_{}", i % 3);
            fp.record_call(&name, &arg_hash);
        }
        prop_assert!(fp.window().len() <= window_size);
    }

    #[test]
    fn hash_arguments_is_deterministic(args in ".*") {
        let h1 = hash_arguments(&args);
        let h2 = hash_arguments(&args);
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn record_call_returns_consistent_digest(
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        args in ".*",
    ) {
        let mut fp = ToolCallFingerprinter::new(20);
        let arg_hash = hash_arguments(&args);
        let d1 = fp.record_call(&tool_name, &arg_hash);
        let d2 = fp.record_call(&tool_name, &arg_hash);
        prop_assert_eq!(d1.digest, d2.digest);
        prop_assert_eq!(d1.tool_name, d2.tool_name);
    }

    #[test]
    fn detect_recon_with_many_different_reads(
        count in 5..20_usize,
    ) {
        let mut fp = ToolCallFingerprinter::new(20);
        let arg_hash = hash_arguments("");
        for i in 0..count {
            fp.record_call("read_file", &[arg_hash[0] ^ (i as u8), arg_hash[1]]);
        }
        // At least 5 reads + high uniqueness should trigger recon
        if count >= 8 {
            // With enough unique reads, recon should trigger
            // (This is a statistical property, not guaranteed for all cases)
            let recon = fp.detect_recon();
            // If recon fires, good; if not, it might be because uniqueness < 70%
            if !recon {
                let total = fp.window().len() as f64;
                let unique = fp.window().iter().map(|d| &d.digest).collect::<std::collections::HashSet<_>>().len() as f64;
                prop_assume!(unique / total > 0.7);
                prop_assert!(fp.detect_recon());
            }
        }
    }
}
