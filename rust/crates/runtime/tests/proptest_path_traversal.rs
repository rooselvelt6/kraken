#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;
use std::path::Path;

proptest! {
    #[test]
    fn detects_dotdot_traversal(
        suffix in "([a-zA-Z0-9_/.-]{0,30})",
    ) {
        let path = format!("../../../etc/passwd{}", suffix);
        let detections = runtime::path_traversal::detect_traversal(&path);
        prop_assert!(
            detections.iter().any(|d| d.kind == runtime::path_traversal::TraversalKind::DirectoryDotDot),
            "expected DirectoryDotDot for path: {}",
            path
        );
    }

    #[test]
    fn detects_dotdot_with_prefix(
        prefix in "[a-zA-Z0-9]{1,5}",
        suffix in "([a-zA-Z0-9_/.-]{0,20})",
    ) {
        let path = format!("{}/../../../etc/passwd{}", prefix, suffix);
        let detections = runtime::path_traversal::detect_traversal(&path);
        prop_assert!(
            detections.iter().any(|d| d.kind == runtime::path_traversal::TraversalKind::DirectoryDotDot),
            "expected DirectoryDotDot for path: {}",
            path
        );
    }

    #[test]
    fn detects_null_byte_traversal(
        before in "([a-zA-Z0-9_/.-]{0,30})",
        after in "([a-zA-Z0-9_/.-]{0,30})",
    ) {
        let path = format!("{}{}{}", before, '\0', after);
        let detections = runtime::path_traversal::detect_traversal(&path);
        prop_assert!(
            detections.iter().any(|d| d.kind == runtime::path_traversal::TraversalKind::NullByte),
            "expected NullByte for path: {:?}",
            path
        );
    }

    #[test]
    fn detects_device_file_traversal(rest in "([a-zA-Z0-9_/.-]{0,50})") {
        let path = format!("/dev/{}", rest);
        let detections = runtime::path_traversal::detect_traversal(&path);
        prop_assert!(
            detections.iter().any(|d| d.kind == runtime::path_traversal::TraversalKind::DeviceFile),
            "expected DeviceFile for path: {}",
            path
        );
    }

    #[test]
    fn safe_path_returns_no_detections(segments in prop::collection::vec("[a-zA-Z0-9._-]{1,20}", 1..5)) {
        let path = segments.join("/");
        let detections = runtime::path_traversal::detect_traversal(&path);
        prop_assert!(
            detections.is_empty(),
            "expected no detections for safe path: {}, got: {:?}",
            path, detections
        );
    }

    #[test]
    fn validate_safe_path_succeeds(segments in prop::collection::vec("[a-zA-Z0-9._-]{1,20}", 1..5)) {
        let path_str = segments.join("/");
        let path = Path::new(&path_str);
        let ws = Path::new("/tmp");
        if !path.exists() {
            let result = runtime::path_traversal::validate_path_safety(path, ws);
            assert!(result.is_ok() || result.as_ref().is_err_and(|e| e.contains("metadata")),
                "validate_path_safety should either succeed or fail with metadata error for non-existent path: {}",
                path_str);
        }
    }

    #[test]
    fn double_encoding_detected(encoding in prop_oneof![
        Just("%252e%252f"),
        Just("%c0%ae%c0%af"),
        Just("%252e%252e%252f"),
        Just("%e0%80%ae%e0%80%af"),
        Just("%%32%65%%32%66"),
    ]) {
        let detections = runtime::path_traversal::detect_traversal(encoding);
        prop_assert!(
            detections.iter().any(|d| d.kind == runtime::path_traversal::TraversalKind::DoubleEncoding),
            "expected DoubleEncoding for: {}",
            encoding
        );
    }
}
