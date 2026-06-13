#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;
use std::path::Path;

proptest! {
    #[test]
    fn sanitize_path_does_not_panic(path: String) {
        let sanitizer = runtime::sanitizer::Sanitizer::with_defaults();
        let result = sanitizer.sanitize_path(&path, None as Option<&Path>);
        let result2 = sanitizer.sanitize_for_read(&path, None as Option<&Path>);
        let result3 = sanitizer.sanitize_for_write(&path, None as Option<&Path>);
        assert!(result.path.components().count() > 0 || !result.issues.is_empty());
        assert!(result2.path.components().count() > 0 || !result2.issues.is_empty());
        assert!(result3.path.components().count() > 0 || !result3.issues.is_empty());
    }

    #[test]
    fn sanitize_with_workspace_no_panic(path: String) {
        let sanitizer = runtime::sanitizer::Sanitizer::with_defaults();
        let ws = Path::new("/tmp");
        let _r1 = sanitizer.sanitize_path(&path, Some(ws));
        let _r2 = sanitizer.sanitize_for_read(&path, Some(ws));
        let _r3 = sanitizer.sanitize_for_write(&path, Some(ws));
    }

    #[test]
    fn allowed_path_is_within_workspace(
        path in "([a-zA-Z0-9._/-]{1,100})", ws_root in "([a-zA-Z0-9._/-]{1,50})"
    ) {
        let sanitizer = runtime::sanitizer::Sanitizer::with_defaults();
        let ws_path = format!("/{}/{}", ws_root.trim_start_matches('/'), path.trim_start_matches('/'));
        let ws_root_str = format!("/{}", ws_root.trim_start_matches('/'));
        let ws_root = Path::new(&ws_root_str);
        let result = sanitizer.sanitize_path(&ws_path, Some(ws_root));
        if result.is_allowed() {
            assert!(result.path.starts_with(ws_root), "allowed path {:?} should start with workspace root {:?}", result.path, ws_root);
        }
    }

    #[test]
    fn sanitize_is_idempotent(path in "([a-zA-Z0-9._/-]{1,60})") {
        let sanitizer = runtime::sanitizer::Sanitizer::with_defaults();
        let r1 = sanitizer.sanitize_path(&path, None as Option<&Path>);
        let r2 = sanitizer.sanitize_path(&r1.path.to_string_lossy(), None as Option<&Path>);
        if r1.is_allowed() {
            assert!(r2.is_allowed(), "re-sanitizing an allowed path should stay allowed");
        }
    }
}
