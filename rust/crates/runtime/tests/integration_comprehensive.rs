use std::path::Path;
use std::time::{Duration, Instant};

#[test]
fn fingerprint_hash_returns_32_bytes() {
    let h = runtime::fingerprint::hash_arguments("test");
    assert_eq!(h.len(), 32);
}

#[test]
fn fingerprint_hash_deterministic() {
    let a = runtime::fingerprint::hash_arguments("hello");
    let b = runtime::fingerprint::hash_arguments("hello");
    assert_eq!(a, b);
}

#[test]
fn fingerprint_hash_varies_by_input() {
    let a = runtime::fingerprint::hash_arguments("abc");
    let b = runtime::fingerprint::hash_arguments("xyz");
    assert_ne!(a, b);
}

#[test]
fn fingerprint_hash_empty() {
    let h = runtime::fingerprint::hash_arguments("");
    assert_eq!(h.len(), 32);
}

#[test]
fn fingerprinter_new_window_empty() {
    let fp = runtime::fingerprint::ToolCallFingerprinter::new(5);
    assert!(fp.window().is_empty());
}

#[test]
fn fingerprinter_record_single() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(10);
    fp.record_call("bash", &runtime::fingerprint::hash_arguments("ls"));
    assert_eq!(fp.window().len(), 1);
}

#[test]
fn fingerprinter_window_respects_max() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(3);
    for i in 0..5 {
        fp.record_call("read_file", &runtime::fingerprint::hash_arguments(&format!("f{i}")));
    }
    assert_eq!(fp.window().len(), 3);
}

#[test]
fn fingerprinter_repetitive_true() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(10);
    let args = runtime::fingerprint::hash_arguments("same");
    for _ in 0..5 {
        fp.record_call("bash", &args);
    }
    assert!(fp.is_repetitive("bash", &args));
}

#[test]
fn fingerprinter_repetitive_false_below_threshold() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(10);
    let args = runtime::fingerprint::hash_arguments("same");
    for _ in 0..3 {
        fp.record_call("bash", &args);
    }
    assert!(!fp.is_repetitive("bash", &args));
}

#[test]
fn fingerprinter_detect_recon_true() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(20);
    for i in 0..8 {
        fp.record_call("read_file", &runtime::fingerprint::hash_arguments(&format!("unique{i}.txt")));
    }
    assert!(fp.detect_recon());
}

#[test]
fn fingerprinter_detect_recon_false_small() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(20);
    for i in 0..3 {
        fp.record_call("read_file", &runtime::fingerprint::hash_arguments(&format!("f{i}")));
    }
    assert!(!fp.detect_recon());
}

#[test]
fn fingerprinter_detect_scan_chain_true() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(20);
    fp.record_call("glob", &runtime::fingerprint::hash_arguments("*"));
    fp.record_call("read_file", &runtime::fingerprint::hash_arguments("f1"));
    fp.record_call("read_file", &runtime::fingerprint::hash_arguments("f2"));
    fp.record_call("read_file", &runtime::fingerprint::hash_arguments("f3"));
    assert!(fp.detect_scan_chain());
}

#[test]
fn fingerprinter_detect_scan_chain_false() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(20);
    fp.record_call("bash", &runtime::fingerprint::hash_arguments("ls"));
    fp.record_call("read_file", &runtime::fingerprint::hash_arguments("f1"));
    fp.record_call("read_file", &runtime::fingerprint::hash_arguments("f2"));
    fp.record_call("read_file", &runtime::fingerprint::hash_arguments("f3"));
    assert!(!fp.detect_scan_chain());
}

#[test]
fn fingerprinter_detect_exfil_true() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(20);
    for i in 0..10 {
        fp.record_call("read_file", &runtime::fingerprint::hash_arguments(&format!("exfil{i}")));
    }
    assert!(fp.detect_exfil());
}

#[test]
fn fingerprinter_detect_exfil_false_with_bash() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(20);
    for i in 0..8 {
        fp.record_call("read_file", &runtime::fingerprint::hash_arguments(&format!("f{i}")));
    }
    fp.record_call("bash", &runtime::fingerprint::hash_arguments("echo"));
    assert!(!fp.detect_exfil());
}

#[test]
fn fingerprinter_reset_clears() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(10);
    let args = runtime::fingerprint::hash_arguments("x");
    fp.record_call("bash", &args);
    fp.reset();
    assert!(fp.window().is_empty());
    assert!(!fp.is_repetitive("bash", &args));
}

#[test]
fn fingerprinter_default_window_20() {
    let fp = runtime::fingerprint::ToolCallFingerprinter::default();
    assert_eq!(fp.window().capacity(), 20);
}

#[test]
fn fingerprinter_digest_differs_by_tool() {
    let mut fp = runtime::fingerprint::ToolCallFingerprinter::new(10);
    let args = runtime::fingerprint::hash_arguments("same");
    let d1 = fp.record_call("tool_a", &args);
    let d2 = fp.record_call("tool_b", &args);
    assert_ne!(d1.digest, d2.digest);
    assert_eq!(d1.tool_name, "tool_a");
    assert_eq!(d2.tool_name, "tool_b");
}

#[test]
fn sanitizer_stage_names() {
    assert_eq!(runtime::sanitizer::SanitizerStage::Normalization.name(), "normalization");
    assert_eq!(runtime::sanitizer::SanitizerStage::Canonicalization.name(), "canonicalization");
    assert_eq!(runtime::sanitizer::SanitizerStage::SymlinkResolution.name(), "symlink_resolution");
    assert_eq!(runtime::sanitizer::SanitizerStage::ScopeCheck.name(), "scope_check");
    assert_eq!(runtime::sanitizer::SanitizerStage::EncodingDetection.name(), "encoding_detection");
    assert_eq!(runtime::sanitizer::SanitizerStage::SizeCheck.name(), "size_check");
    assert_eq!(runtime::sanitizer::SanitizerStage::Allowlist.name(), "allowlist");
}

#[test]
fn sanitizer_issue_descriptions() {
    use runtime::sanitizer::SanitizerIssue;
    assert!(SanitizerIssue::PathTraversal("/etc".into()).description().contains("path traversal"));
    assert!(SanitizerIssue::SymlinkEscape("/tmp".into()).description().contains("symlink"));
    assert!(SanitizerIssue::OutOfScope("/out".into()).description().contains("outside"));
    assert!(SanitizerIssue::EncodingAttack("%2e".into()).description().contains("encoding"));
    assert!(SanitizerIssue::NullByte("f".into()).description().contains("null byte"));
    assert!(SanitizerIssue::DeviceFile("/dev".into()).description().contains("device"));
    assert!(SanitizerIssue::BinaryFile("b".into()).description().contains("binary"));
    assert!(SanitizerIssue::SizeLimitExceeded { limit: 1024, actual: 2048 }.description().contains("1024"));
}

#[test]
fn sanitizer_allows_normal_file() {
    let dir = std::env::temp_dir().join(format!("san-i-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ok.txt"), "hello").unwrap();
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    let r = s.sanitize_for_read(dir.join("ok.txt").to_str().unwrap(), None);
    assert!(r.is_allowed());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sanitizer_rejects_null_byte() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(!s.sanitize_for_read("file\u{0}.txt", None).is_allowed());
}

#[test]
fn sanitizer_rejects_dev_null() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(!s.sanitize_for_read("/dev/null", None).is_allowed());
}

#[test]
fn sanitizer_rejects_proc() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(!s.sanitize_for_read("/proc/self/fd/0", None).is_allowed());
}

#[test]
fn sanitizer_rejects_sys() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(!s.sanitize_for_read("/sys/kernel/irq", None).is_allowed());
}

#[test]
fn sanitizer_seven_stages() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    let r = s.sanitize_for_read("src/lib.rs", None);
    assert_eq!(r.stages_passed.len(), 7);
}

#[test]
fn sanitizer_custom_max_read_size() {
    let dir = std::env::temp_dir().join(format!("san-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), vec![0u8; 200]).unwrap();
    let mut cfg = runtime::sanitizer::SanitizerConfig::default();
    cfg.max_read_size = 100;
    let s = runtime::sanitizer::Sanitizer::new(cfg);
    let r = s.sanitize_for_read(dir.join("big.bin").to_str().unwrap(), None);
    assert!(r.issues.iter().any(|i| matches!(i, runtime::sanitizer::SanitizerIssue::SizeLimitExceeded { .. })));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sanitizer_write_rejects_device() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(!s.sanitize_for_write("/dev/sda", None).is_allowed());
}

#[test]
fn sanitizer_path_allows_normal() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(s.sanitize_path("src/main.rs", None).is_allowed());
}

#[test]
fn sanitizer_out_of_scope() {
    let dir = std::env::temp_dir().join(format!("san-s-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ws = dir.join("workspace");
    std::fs::create_dir(&ws).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "data").unwrap();
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    let r = s.sanitize_for_read(outside.to_str().unwrap(), Some(&ws));
    assert!(r.issues.iter().any(|i| matches!(i, runtime::sanitizer::SanitizerIssue::OutOfScope(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sanitizer_file_op_counter() {
    let before = runtime::sanitizer::file_op_count();
    runtime::sanitizer::track_file_operation();
    runtime::sanitizer::track_file_operation();
    assert!(runtime::sanitizer::file_op_count() >= before + 2);
}

#[test]
fn sanitizer_result_allowed_empty_issues() {
    let r = runtime::sanitizer::SanitizerResult {
        path: std::path::PathBuf::from("test"),
        stages_passed: vec![],
        issues: vec![],
    };
    assert!(r.is_allowed());
}

#[test]
fn sanitizer_result_not_allowed_with_issues() {
    let r = runtime::sanitizer::SanitizerResult {
        path: std::path::PathBuf::from("test"),
        stages_passed: vec![],
        issues: vec![runtime::sanitizer::SanitizerIssue::NullByte("x".into())],
    };
    assert!(!r.is_allowed());
}

#[test]
fn sanitizer_dotdot_resolution() {
    let s = runtime::sanitizer::Sanitizer::with_defaults();
    assert!(s.sanitize_for_read("foo/../bar/baz.rs", None).is_allowed());
}

#[test]
fn task_registry_new_empty() {
    let reg = runtime::task_registry::TaskRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn task_registry_create() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("Fix bug", Some("critical"));
    assert_eq!(t.status, runtime::task_registry::TaskStatus::Created);
    assert_eq!(t.prompt, "Fix bug");
    assert_eq!(t.description.as_deref(), Some("critical"));
    assert!(t.task_id.starts_with("task_"));
}

#[test]
fn task_registry_create_no_desc() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("Do", None);
    assert_eq!(t.description, None);
    assert!(t.messages.is_empty());
}

#[test]
fn task_registry_get_exists() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("A", None);
    assert!(reg.get(&t.task_id).is_some());
}

#[test]
fn task_registry_get_missing() {
    let reg = runtime::task_registry::TaskRegistry::new();
    assert!(reg.get("nope").is_none());
}

#[test]
fn task_registry_list_all() {
    let reg = runtime::task_registry::TaskRegistry::new();
    reg.create("A", None);
    reg.create("B", None);
    reg.create("C", None);
    assert_eq!(reg.list(None).len(), 3);
}

#[test]
fn task_registry_list_filtered() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("B", None);
    reg.set_status(&t.task_id, runtime::task_registry::TaskStatus::Running).unwrap();
    assert_eq!(reg.list(Some(runtime::task_registry::TaskStatus::Created)).len(), 0);
    assert_eq!(reg.list(Some(runtime::task_registry::TaskStatus::Running)).len(), 1);
}

#[test]
fn task_registry_stop_running() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("X", None);
    reg.set_status(&t.task_id, runtime::task_registry::TaskStatus::Running).unwrap();
    assert_eq!(reg.stop(&t.task_id).unwrap().status, runtime::task_registry::TaskStatus::Stopped);
}

#[test]
fn task_registry_stop_rejects_terminal() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("D", None);
    reg.set_status(&t.task_id, runtime::task_registry::TaskStatus::Completed).unwrap();
    assert!(reg.stop(&t.task_id).is_err());
    let t2 = reg.create("F", None);
    reg.set_status(&t2.task_id, runtime::task_registry::TaskStatus::Failed).unwrap();
    assert!(reg.stop(&t2.task_id).is_err());
}

#[test]
fn task_registry_update() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("M", None);
    let u = reg.update(&t.task_id, "info").unwrap();
    assert_eq!(u.messages.len(), 1);
    assert_eq!(u.messages[0].content, "info");
}

#[test]
fn task_registry_output() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("O", None);
    reg.append_output(&t.task_id, "a").unwrap();
    reg.append_output(&t.task_id, "b").unwrap();
    assert_eq!(reg.output(&t.task_id).unwrap(), "ab");
}

#[test]
fn task_registry_team() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("T", None);
    reg.assign_team(&t.task_id, "alpha").unwrap();
    assert_eq!(reg.get(&t.task_id).unwrap().team_id.as_deref(), Some("alpha"));
}

#[test]
fn task_registry_remove() {
    let reg = runtime::task_registry::TaskRegistry::new();
    let t = reg.create("R", None);
    assert!(reg.remove(&t.task_id).is_some());
    assert!(reg.get(&t.task_id).is_none());
}

#[test]
fn task_registry_errors_on_missing() {
    let reg = runtime::task_registry::TaskRegistry::new();
    assert!(reg.stop("x").is_err());
    assert!(reg.update("x", "m").is_err());
    assert!(reg.output("x").is_err());
    assert!(reg.append_output("x", "o").is_err());
    assert!(reg.set_status("x", runtime::task_registry::TaskStatus::Running).is_err());
    assert!(reg.assign_team("x", "t").is_err());
}

#[test]
fn task_status_display() {
    use runtime::task_registry::TaskStatus;
    assert_eq!(TaskStatus::Created.to_string(), "created");
    assert_eq!(TaskStatus::Running.to_string(), "running");
    assert_eq!(TaskStatus::Completed.to_string(), "completed");
    assert_eq!(TaskStatus::Failed.to_string(), "failed");
    assert_eq!(TaskStatus::Stopped.to_string(), "stopped");
}

#[test]
fn traversal_empty_for_safe() {
    assert!(runtime::path_traversal::detect_traversal("/home/user/file.txt").is_empty());
}

#[test]
fn traversal_dotdot() {
    let d = runtime::path_traversal::detect_traversal("../../../etc/passwd");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::DirectoryDotDot));
}

#[test]
fn traversal_null_byte() {
    let d = runtime::path_traversal::detect_traversal("file\u{0}.txt");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::NullByte));
}

#[test]
fn traversal_device() {
    let d = runtime::path_traversal::detect_traversal("/dev/sda");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::DeviceFile));
}

#[test]
fn traversal_proc() {
    let d = runtime::path_traversal::detect_traversal("/proc/self/fd/0");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::ProcSelfFd));
}

#[test]
fn traversal_double_encoding() {
    let d = runtime::path_traversal::detect_traversal("%252e%252f");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::DoubleEncoding));
}

#[test]
fn traversal_windows_ads() {
    let d = runtime::path_traversal::detect_traversal("file.txt::$DATA");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::WindowsAlternateDataStream));
}

#[test]
fn traversal_unicode() {
    let d = runtime::path_traversal::detect_traversal("\u{FF0E}\u{FF0F}");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::UnicodeNormalization));
}

#[test]
fn traversal_multiple_threats() {
    let d = runtime::path_traversal::detect_traversal("/proc/self/fd/0\u{0}../../../etc");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::ProcSelfFd));
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::NullByte));
}

#[test]
fn traversal_sys_device() {
    let d = runtime::path_traversal::detect_traversal("/sys/kernel/irq");
    assert!(d.iter().any(|x| x.kind == runtime::path_traversal::TraversalKind::DeviceFile));
}

#[test]
fn traversal_kind_descriptions_all() {
    assert!(!runtime::path_traversal::TraversalKind::DirectoryDotDot.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::NullByte.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::DeviceFile.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::ProcSelfFd.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::DoubleEncoding.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::UnicodeNormalization.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::WindowsAlternateDataStream.description().is_empty());
    assert!(!runtime::path_traversal::TraversalKind::FifoPipe.description().is_empty());
}

#[test]
fn enforcer_allow_permits_all() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::Allow));
    assert!(e.is_allowed("bash", "rm -rf /"));
    assert!(e.is_allowed("write_file", "data"));
}

#[test]
fn enforcer_read_only_denies_write() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::ReadOnly)
            .with_tool_requirement("read_file", runtime::PermissionMode::ReadOnly));
    assert!(e.is_allowed("read_file", "path"));
    assert!(!e.is_allowed("write_file", "data"));
}

#[test]
fn enforcer_bash_read_only_cat() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::ReadOnly));
    assert!(matches!(e.check_bash("cat file.txt"), runtime::permission_enforcer::EnforcementResult::Allowed));
}

#[test]
fn enforcer_bash_read_only_rm() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::ReadOnly));
    assert!(matches!(e.check_bash("rm file.txt"), runtime::permission_enforcer::EnforcementResult::Denied { .. }));
}

#[test]
fn enforcer_bash_prompt_denies() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::Prompt));
    assert!(matches!(e.check_bash("echo hi"), runtime::permission_enforcer::EnforcementResult::Denied { .. }));
}

#[test]
fn enforcer_file_write_within_workspace() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::WorkspaceWrite));
    assert_eq!(e.check_file_write("/workspace/src/main.rs", "/workspace"), runtime::permission_enforcer::EnforcementResult::Allowed);
}

#[test]
fn enforcer_file_write_outside_workspace() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::WorkspaceWrite));
    assert!(matches!(e.check_file_write("/etc/passwd", "/workspace"), runtime::permission_enforcer::EnforcementResult::Denied { .. }));
}

#[test]
fn enforcer_danger_full_access() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::DangerFullAccess));
    assert_eq!(e.check_file_write("/anywhere", "/ws"), runtime::permission_enforcer::EnforcementResult::Allowed);
    assert_eq!(e.check_bash("rm -rf /"), runtime::permission_enforcer::EnforcementResult::Allowed);
}

#[test]
fn enforcer_active_mode() {
    let modes = [runtime::PermissionMode::ReadOnly, runtime::PermissionMode::WorkspaceWrite,
        runtime::PermissionMode::DangerFullAccess, runtime::PermissionMode::Allow];
    for mode in modes {
        let e = runtime::permission_enforcer::PermissionEnforcer::new(runtime::PermissionPolicy::new(mode));
        assert_eq!(e.active_mode(), mode);
    }
}

#[test]
fn enforcer_denied_fields() {
    let policy = runtime::PermissionPolicy::new(runtime::PermissionMode::ReadOnly)
        .with_tool_requirement("write_file", runtime::PermissionMode::WorkspaceWrite);
    let e = runtime::permission_enforcer::PermissionEnforcer::new(policy);
    match e.check("write_file", "{}") {
        runtime::permission_enforcer::EnforcementResult::Denied { tool, active_mode, required_mode, .. } => {
            assert_eq!(tool, "write_file");
            assert_eq!(active_mode, "read-only");
            assert_eq!(required_mode, "workspace-write");
        }
        other => panic!("expected denied, got {other:?}"),
    }
}

#[test]
fn enforcer_relative_path() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::WorkspaceWrite));
    assert_eq!(e.check_file_write("src/main.rs", "/workspace"), runtime::permission_enforcer::EnforcementResult::Allowed);
}

#[test]
fn enforcer_prompt_check_allows() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::Prompt));
    assert!(matches!(e.check("write_file", "{}"), runtime::permission_enforcer::EnforcementResult::Allowed));
}

#[test]
fn enforcer_read_only_various_commands() {
    let e = runtime::permission_enforcer::PermissionEnforcer::new(
        runtime::PermissionPolicy::new(runtime::PermissionMode::ReadOnly));
    assert_eq!(e.check_bash("ls"), runtime::permission_enforcer::EnforcementResult::Allowed);
    assert_eq!(e.check_bash("grep pattern file"), runtime::permission_enforcer::EnforcementResult::Allowed);
    assert_eq!(e.check_bash("git log"), runtime::permission_enforcer::EnforcementResult::Allowed);
    assert!(matches!(e.check_bash("rm file"), runtime::permission_enforcer::EnforcementResult::Denied { .. }));
    assert!(matches!(e.check_bash("cp a b"), runtime::permission_enforcer::EnforcementResult::Denied { .. }));
}

#[test]
fn green_satisfied_exact() {
    let c = runtime::green_contract::GreenContract::new(runtime::green_contract::GreenLevel::Package);
    assert!(c.evaluate(Some(runtime::green_contract::GreenLevel::Package)).is_satisfied());
}

#[test]
fn green_satisfied_higher() {
    let c = runtime::green_contract::GreenContract::new(runtime::green_contract::GreenLevel::TargetedTests);
    assert!(c.is_satisfied_by(runtime::green_contract::GreenLevel::Workspace));
}

#[test]
fn green_unsatisfied_lower() {
    let c = runtime::green_contract::GreenContract::new(runtime::green_contract::GreenLevel::Workspace);
    assert!(!c.evaluate(Some(runtime::green_contract::GreenLevel::Package)).is_satisfied());
}

#[test]
fn green_unsatisfied_none() {
    let c = runtime::green_contract::GreenContract::new(runtime::green_contract::GreenLevel::MergeReady);
    assert!(!c.evaluate(None).is_satisfied());
}

#[test]
fn green_level_ordering() {
    use runtime::green_contract::GreenLevel;
    assert!(GreenLevel::TargetedTests < GreenLevel::Package);
    assert!(GreenLevel::Package < GreenLevel::Workspace);
    assert!(GreenLevel::Workspace < GreenLevel::MergeReady);
}

#[test]
fn green_level_as_str() {
    use runtime::green_contract::GreenLevel;
    assert_eq!(GreenLevel::TargetedTests.as_str(), "targeted_tests");
    assert_eq!(GreenLevel::Package.as_str(), "package");
    assert_eq!(GreenLevel::Workspace.as_str(), "workspace");
    assert_eq!(GreenLevel::MergeReady.as_str(), "merge_ready");
}

#[test]
fn green_display() {
    use runtime::green_contract::GreenLevel;
    assert_eq!(format!("{}", GreenLevel::Package), "package");
}

#[test]
fn green_outcome_display() {
    use runtime::green_contract::{GreenContract, GreenContractOutcome, GreenLevel};
    let c = GreenContract::new(GreenLevel::Workspace);
    match c.evaluate(Some(GreenLevel::Workspace)) {
        GreenContractOutcome::Satisfied { .. } => {}
        other => panic!("expected satisfied, got {other:?}"),
    }
}

#[test]
fn forensic_entry_new() {
    let e = runtime::forensic::ForensicEntry::new("test");
    assert_eq!(e.event_type, "test");
    assert!(e.data.is_empty());
}

#[test]
fn forensic_entry_with_data() {
    let e = runtime::forensic::ForensicEntry::new("cmd").with("k1", "v1").with("k2", "v2");
    assert_eq!(e.data.len(), 2);
    assert_eq!(e.data.get("k1").unwrap(), "v1");
}

#[test]
fn forensic_entry_json() {
    let e = runtime::forensic::ForensicEntry::new("test").with("key", "val");
    let json = e.to_json();
    assert_eq!(json["event_type"], "test");
    assert_eq!(json["data"]["key"], "val");
    assert!(json["timestamp"].is_number());
}

#[test]
fn forensic_entry_capture_id_increments() {
    let e1 = runtime::forensic::ForensicEntry::new("a");
    let e2 = runtime::forensic::ForensicEntry::new("b");
    assert!(e2.capture_id > e1.capture_id);
}

#[test]
fn forensic_recorder_disabled() {
    let mut r = runtime::forensic::ForensicRecorder::new(100);
    assert!(!r.is_enabled());
    r.record(runtime::forensic::ForensicEntry::new("e"));
    assert!(r.is_empty());
}

#[test]
fn forensic_recorder_enable_and_record() {
    let mut r = runtime::forensic::ForensicRecorder::new(100);
    let dir = std::env::temp_dir().join(format!("forensic-{}", std::process::id()));
    r.enable(dir.clone());
    assert!(r.is_enabled());
    r.record(runtime::forensic::ForensicEntry::new("e1"));
    r.record(runtime::forensic::ForensicEntry::new("e2"));
    assert_eq!(r.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_max_entries() {
    let mut r = runtime::forensic::ForensicRecorder::new(3);
    let dir = std::env::temp_dir().join(format!("forensic-max-{}", std::process::id()));
    r.enable(dir.clone());
    for i in 0..5 {
        r.record(runtime::forensic::ForensicEntry::new(&format!("e{i}")));
    }
    assert_eq!(r.len(), 3);
    assert_eq!(r.entries()[0].event_type, "e2");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_export_json() {
    let mut r = runtime::forensic::ForensicRecorder::new(100);
    let dir = std::env::temp_dir().join(format!("forensic-exp-{}", std::process::id()));
    r.enable(dir.clone());
    r.record(runtime::forensic::ForensicEntry::new("a"));
    r.record(runtime::forensic::ForensicEntry::new("b"));
    assert_eq!(r.export_json().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_capture_command() {
    let mut r = runtime::forensic::ForensicRecorder::new(100);
    let dir = std::env::temp_dir().join(format!("forensic-cmd-{}", std::process::id()));
    r.enable(dir.clone());
    r.capture_command("bash", &["-c".into(), "echo hi".into()]);
    assert_eq!(r.len(), 1);
    assert_eq!(r.entries()[0].event_type, "command");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_capture_file_ops() {
    let mut r = runtime::forensic::ForensicRecorder::new(100);
    let dir = std::env::temp_dir().join(format!("forensic-file-{}", std::process::id()));
    r.enable(dir.clone());
    r.capture_file_read("/etc/passwd");
    r.capture_file_write("/tmp/t.txt", 1024);
    assert_eq!(r.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_capture_network() {
    let mut r = runtime::forensic::ForensicRecorder::new(100);
    let dir = std::env::temp_dir().join(format!("forensic-net-{}", std::process::id()));
    r.enable(dir.clone());
    r.capture_network("https://api.example.com", "POST");
    assert_eq!(r.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_entry_with_env() {
    std::env::set_var("KRaken_TEST_ENV_VAR", "test123");
    let e = runtime::forensic::ForensicEntry::new("env").with_env();
    assert!(e.data.contains_key("env:KRaken_TEST_ENV_VAR"));
}

#[test]
fn global_forensic_exists() {
    let f = runtime::forensic::global_forensic();
    let guard = f.lock().unwrap();
    assert!(!guard.is_enabled());
}

#[test]
fn circuit_node_default_closed() {
    let n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 3, Duration::from_secs(30));
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Closed);
    assert!(n.can_execute());
}

#[test]
fn circuit_opens_after_failures() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 3, Duration::from_secs(30));
    n.record_failure();
    n.record_failure();
    n.record_failure();
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Open);
    assert!(!n.can_execute());
}

#[test]
fn circuit_stays_closed_below_threshold() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 5, Duration::from_secs(30));
    n.record_failure();
    n.record_failure();
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Closed);
}

#[test]
fn circuit_recovery_after_timeout() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 2, Duration::from_millis(1));
    n.record_failure();
    n.record_failure();
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Open);
    std::thread::sleep(Duration::from_millis(5));
    assert!(n.can_execute());
}

#[test]
fn circuit_half_open_to_closed() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 2, Duration::from_millis(1));
    n.record_failure();
    n.record_failure();
    std::thread::sleep(Duration::from_millis(5));
    n.record_success(10.0);
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::HalfOpen);
    n.record_success(10.0);
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Closed);
}

#[test]
fn circuit_half_open_fails_to_open() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 2, Duration::from_millis(1));
    n.record_failure();
    n.record_failure();
    std::thread::sleep(Duration::from_millis(5));
    n.record_success(10.0);
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::HalfOpen);
    n.record_failure();
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Open);
}

#[test]
fn circuit_latency_percentiles() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 3, Duration::from_secs(30));
    for i in 1..=10 {
        n.record_success(f64::from(i) * 10.0);
    }
    assert!(n.latency_p50_ms > 0.0);
    assert!(n.latency_p95_ms >= n.latency_p50_ms);
}

#[test]
fn circuit_failure_rate() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 3, Duration::from_secs(30));
    assert_eq!(n.failure_rate(), 0.0);
    n.record_failure();
    n.record_failure();
    assert!((n.failure_rate() - 1.0).abs() < 0.001);
}

#[test]
fn circuit_recovery_time_remaining() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 1, Duration::from_hours(1));
    n.record_failure();
    assert!(n.recovery_time_remaining().is_some());
}

#[test]
fn circuit_no_recovery_when_closed() {
    let n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 3, Duration::from_secs(30));
    assert!(n.recovery_time_remaining().is_none());
}

#[test]
fn circuit_reset() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 2, Duration::from_secs(30));
    n.record_failure();
    n.record_failure();
    n.reset();
    assert!(n.is_healthy());
}

#[test]
fn circuit_level_parent() {
    use runtime::circuit_breaker::CircuitLevel;
    assert_eq!(CircuitLevel::Tool.parent(), Some(CircuitLevel::Provider));
    assert_eq!(CircuitLevel::Provider.parent(), Some(CircuitLevel::Global));
    assert_eq!(CircuitLevel::McpServer.parent(), Some(CircuitLevel::Global));
    assert_eq!(CircuitLevel::Global.parent(), None);
}

#[test]
fn circuit_forest_register() {
    let mut f = runtime::circuit_breaker::CircuitForest::new();
    f.register("p1", runtime::circuit_breaker::CircuitLevel::Provider, 5, Duration::from_secs(30));
    assert!(f.get("p1").is_some());
}

#[test]
fn circuit_forest_hierarchical() {
    let mut f = runtime::circuit_breaker::CircuitForest::new();
    f.register("global", runtime::circuit_breaker::CircuitLevel::Global, 3, Duration::from_mins(1));
    f.register("prov1", runtime::circuit_breaker::CircuitLevel::Provider, 3, Duration::from_secs(30));
    f.record_failure("prov1");
    f.record_failure("prov1");
    f.record_failure("prov1");
    assert!(!f.can_execute("prov1"));
}

#[test]
fn circuit_forest_degraded_providers() {
    let mut f = runtime::circuit_breaker::CircuitForest::new();
    f.register("p1", runtime::circuit_breaker::CircuitLevel::Provider, 1, Duration::from_hours(1));
    f.register("p2", runtime::circuit_breaker::CircuitLevel::Provider, 1, Duration::from_hours(1));
    f.record_failure("p1");
    let d = f.degraded_providers();
    assert!(d.contains(&"p1".to_string()));
    assert!(!d.contains(&"p2".to_string()));
}

#[test]
fn circuit_forest_open_circuits() {
    let mut f = runtime::circuit_breaker::CircuitForest::new();
    f.register("p1", runtime::circuit_breaker::CircuitLevel::Provider, 1, Duration::from_hours(1));
    f.register("p2", runtime::circuit_breaker::CircuitLevel::Provider, 1, Duration::from_hours(1));
    f.record_failure("p1");
    assert_eq!(f.open_circuits().len(), 1);
}

#[test]
fn circuit_forest_reset() {
    let mut f = runtime::circuit_breaker::CircuitForest::new();
    f.register("p1", runtime::circuit_breaker::CircuitLevel::Provider, 1, Duration::from_hours(1));
    f.record_failure("p1");
    f.reset("p1");
    assert!(f.is_healthy("p1"));
}

#[test]
fn circuit_consecutive_timeouts() {
    let mut n = runtime::circuit_breaker::CircuitNode::new("t", runtime::circuit_breaker::CircuitLevel::Tool, 1, Duration::from_hours(1));
    n.record_timeout(5000.0);
    assert_eq!(n.state, runtime::circuit_breaker::CircuitState::Open);
}

#[test]
fn concurrency_category_limits() {
    use runtime::concurrency::ConcurrencyCategory;
    assert_eq!(ConcurrencyCategory::Bash.default_limit(), 5);
    assert_eq!(ConcurrencyCategory::Read.default_limit(), 20);
    assert_eq!(ConcurrencyCategory::Write.default_limit(), 3);
    assert_eq!(ConcurrencyCategory::Search.default_limit(), 2);
    assert_eq!(ConcurrencyCategory::Mcp.default_limit(), 10);
}

#[test]
fn concurrency_category_names() {
    use runtime::concurrency::ConcurrencyCategory;
    assert_eq!(ConcurrencyCategory::Bash.name(), "bash");
    assert_eq!(ConcurrencyCategory::Read.name(), "read");
    assert_eq!(ConcurrencyCategory::Write.name(), "write");
    assert_eq!(ConcurrencyCategory::Search.name(), "search");
    assert_eq!(ConcurrencyCategory::Mcp.name(), "mcp");
}

#[tokio::test]
async fn concurrency_acquire() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let g = m.acquire(runtime::concurrency::ConcurrencyCategory::Bash).await;
    assert!(g.is_some());
}

#[tokio::test]
async fn concurrency_try_acquire() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    assert!(m.try_acquire(runtime::concurrency::ConcurrencyCategory::Bash).is_some());
}

#[tokio::test]
async fn concurrency_limits() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    assert_eq!(m.limit(runtime::concurrency::ConcurrencyCategory::Bash), 5);
    assert_eq!(m.limit(runtime::concurrency::ConcurrencyCategory::Read), 20);
}

#[tokio::test]
async fn concurrency_not_throttled_default() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    assert!(!m.is_throttled(runtime::concurrency::ConcurrencyCategory::Bash));
}

#[tokio::test]
async fn concurrency_active_count() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let _g = m.acquire(runtime::concurrency::ConcurrencyCategory::Bash).await;
    assert_eq!(m.active_count(runtime::concurrency::ConcurrencyCategory::Bash), 1);
}

#[tokio::test]
async fn concurrency_available_permits() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let _g = m.acquire(runtime::concurrency::ConcurrencyCategory::Bash).await;
    assert_eq!(m.available_permits(runtime::concurrency::ConcurrencyCategory::Bash), 4);
}

#[tokio::test]
async fn concurrency_set_limit() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    m.set_limit(runtime::concurrency::ConcurrencyCategory::Bash, 10);
    assert_eq!(m.limit(runtime::concurrency::ConcurrencyCategory::Bash), 10);
}

#[tokio::test]
async fn concurrency_exhausted() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    m.set_limit(runtime::concurrency::ConcurrencyCategory::Bash, 1);
    let _g = m.acquire(runtime::concurrency::ConcurrencyCategory::Bash).await;
    assert!(m.is_throttled(runtime::concurrency::ConcurrencyCategory::Bash));
}

#[tokio::test]
async fn concurrency_guard_drop() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let g = m.acquire(runtime::concurrency::ConcurrencyCategory::Bash).await;
    drop(g);
    for _ in 0..5 {
        assert!(m.try_acquire(runtime::concurrency::ConcurrencyCategory::Bash).is_some());
    }
}

#[tokio::test]
async fn concurrency_status() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let _g = m.acquire(runtime::concurrency::ConcurrencyCategory::Bash).await;
    let statuses = m.status();
    let bs = statuses.iter().find(|s| s.name == "bash").unwrap();
    assert_eq!(bs.active, 1);
    assert_eq!(bs.available, 4);
}

#[tokio::test]
async fn concurrency_guard_category() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let g = m.acquire(runtime::concurrency::ConcurrencyCategory::Write).await.unwrap();
    assert_eq!(g.category(), runtime::concurrency::ConcurrencyCategory::Write);
}

#[tokio::test]
async fn concurrency_concurrent_acquire() {
    let m = runtime::concurrency::ConcurrencyManager::new();
    let mut guards = Vec::new();
    for _ in 0..5 {
        guards.push(m.try_acquire(runtime::concurrency::ConcurrencyCategory::Bash).unwrap());
    }
    assert_eq!(m.active_count(runtime::concurrency::ConcurrencyCategory::Bash), 5);
    assert!(m.try_acquire(runtime::concurrency::ConcurrencyCategory::Bash).is_none());
    drop(guards.remove(0));
    assert_eq!(m.active_count(runtime::concurrency::ConcurrencyCategory::Bash), 4);
    assert!(m.try_acquire(runtime::concurrency::ConcurrencyCategory::Bash).is_some());
}

#[test]
fn rate_limiter_bucket_initial() {
    let b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    assert_eq!(b.name, "test");
    assert!(b.utilization() > 0.99);
}

#[test]
fn rate_limiter_allow_success() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    assert!(b.allow(50.0));
    assert!((b.remaining() - 50.0).abs() < 0.01);
}

#[test]
fn rate_limiter_allow_failure() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    assert!(!b.allow(150.0));
}

#[test]
fn rate_limiter_try_consume() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    assert!(b.try_consume(50.0).is_ok());
    assert!(b.try_consume(60.0).is_err());
}

#[test]
fn rate_limiter_refill() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 50.0, 200.0, 10.0);
    assert!(b.allow(100.0));
    assert_eq!(b.remaining(), 0.0);
    std::thread::sleep(Duration::from_millis(100));
    b.try_consume(0.0).ok();
    assert!(b.remaining() > 0.0);
}

#[test]
fn rate_limiter_exhausted() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 1.0, 0.01, 1.0, 1.0);
    assert!(b.allow(1.0));
    assert!(b.is_exhausted());
}

#[test]
fn rate_limiter_reset() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    b.allow(50.0);
    b.record_error();
    b.reset();
    assert!((b.remaining() - 100.0).abs() < 0.01);
}

#[test]
fn rate_limiter_adjust_confidence() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    b.last_adjustment = Instant::now().checked_sub(Duration::from_secs(31)).unwrap();
    b.request_count = 100;
    b.error_count = 2;
    b.adjust();
    assert!(b.confidence_bonus > 0.0);
}

#[test]
fn rate_limiter_adjust_malus() {
    let mut b = runtime::rate_limiter::AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
    b.last_adjustment = Instant::now().checked_sub(Duration::from_secs(31)).unwrap();
    b.request_count = 100;
    b.error_count = 30;
    b.adjust();
    assert!(b.error_malus > 0.0);
}

#[test]
fn rate_limiter_registry() {
    let mut r = runtime::rate_limiter::TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("p1");
    assert!(r.allow("p1", 10.0));
    assert_eq!(r.remaining("p1"), Some(50.0));
}

#[test]
fn rate_limiter_registry_unknown() {
    let mut r = runtime::rate_limiter::TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    assert!(r.allow("unknown", 10.0));
}

#[test]
fn rate_limiter_registry_names() {
    let mut r = runtime::rate_limiter::TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("p1");
    r.register("p2");
    assert_eq!(r.bucket_names().len(), 2);
}

#[test]
fn rate_limiter_registry_reset() {
    let mut r = runtime::rate_limiter::TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("p1");
    r.allow("p1", 30.0);
    r.reset("p1");
    assert_eq!(r.remaining("p1"), Some(60.0));
}

#[test]
fn rate_limiter_global_exists() {
    let limiter = runtime::rate_limiter::global_rate_limiter();
    let mut guard = limiter.lock().unwrap();
    assert!(guard.get_mut("anthropic").is_some());
}

#[test]
fn health_probe_latency_window() {
    let mut w = runtime::health_probe::LatencyWindow::new(10);
    w.record(10.0);
    w.record(20.0);
    w.record(30.0);
    assert_eq!(w.p50(), Some(20.0));
    assert!(!w.is_empty());
    assert_eq!(w.len(), 3);
}

#[test]
fn health_probe_latency_empty() {
    let w = runtime::health_probe::LatencyWindow::new(10);
    assert!(w.p50().is_none());
    assert!(w.average().is_none());
}

#[test]
fn health_probe_latency_max_capacity() {
    let mut w = runtime::health_probe::LatencyWindow::new(3);
    w.record(1.0);
    w.record(2.0);
    w.record(3.0);
    w.record(4.0);
    assert_eq!(w.len(), 3);
    assert_eq!(w.max(), Some(4.0));
}

#[test]
fn health_probe_target_initial() {
    let t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
    assert_eq!(t.status, runtime::health_probe::HealthStatus::Unknown);
    assert!(t.due_for_probe());
    assert!(t.is_available());
}

#[test]
fn health_probe_target_healthy_after_successes() {
    let mut t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
    t.record_success(100.0);
    t.record_success(100.0);
    t.record_success(100.0);
    assert_eq!(t.status, runtime::health_probe::HealthStatus::Healthy);
}

#[test]
fn health_probe_target_degraded_high_latency() {
    let mut t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 500.0);
    t.record_success(600.0);
    assert_eq!(t.status, runtime::health_probe::HealthStatus::Degraded);
}

#[test]
fn health_probe_target_unhealthy() {
    let mut t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
    for _ in 0..5 {
        t.record_failure(1000.0);
    }
    assert_eq!(t.status, runtime::health_probe::HealthStatus::Unhealthy);
    assert!(!t.is_available());
}

#[test]
fn health_probe_target_error_rate() {
    let mut t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
    assert_eq!(t.error_rate(), 0.0);
    t.record_success(100.0);
    t.record_failure(100.0);
    assert!((t.error_rate() - 0.5).abs() < 0.001);
}

#[test]
fn health_probe_report_should_degrade() {
    let mut t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
    for _ in 0..10 { t.record_success(6000.0); }
    let r = t.report();
    assert!(r.should_degrade());
}

#[test]
fn health_probe_report_open_circuit() {
    let mut t = runtime::health_probe::ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
    for _ in 0..6 { t.record_failure(12000.0); }
    let r = t.report();
    assert!(r.should_open_circuit());
}

#[test]
fn health_probe_registry() {
    let mut r = runtime::health_probe::HealthProbeRegistry::new();
    r.register(runtime::health_probe::ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
    assert!(r.get("p1").is_some());
    assert!(r.get("p2").is_none());
}

#[test]
fn health_probe_registry_remove() {
    let mut r = runtime::health_probe::HealthProbeRegistry::new();
    r.register(runtime::health_probe::ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
    r.remove("p1");
    assert!(r.get("p1").is_none());
}

#[test]
fn health_probe_registry_unhealthy() {
    let mut r = runtime::health_probe::HealthProbeRegistry::new();
    r.register(runtime::health_probe::ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
    for _ in 0..5 { r.record_failure("p1", 1000.0); }
    assert_eq!(r.unhealthy_targets(), vec!["p1".to_string()]);
}

#[test]
fn health_probe_registry_reports() {
    let mut r = runtime::health_probe::HealthProbeRegistry::new();
    r.register(runtime::health_probe::ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
    r.record_success("p1", 100.0);
    assert_eq!(r.reports().len(), 1);
}

#[test]
fn health_probe_registry_due() {
    let mut r = runtime::health_probe::HealthProbeRegistry::new();
    r.register(runtime::health_probe::ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
    assert_eq!(r.due_targets(), vec!["p1".to_string()]);
}

#[test]
fn heuristic_risk_level_ordering() {
    use runtime::heuristic_engine::RiskLevel;
    assert!(RiskLevel::Safe < RiskLevel::Low);
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

#[test]
fn heuristic_risk_level_from_score() {
    use runtime::heuristic_engine::RiskLevel;
    assert_eq!(RiskLevel::from_score(0.0), RiskLevel::Safe);
    assert_eq!(RiskLevel::from_score(0.5), RiskLevel::Low);
    assert_eq!(RiskLevel::from_score(0.7), RiskLevel::Medium);
    assert_eq!(RiskLevel::from_score(0.9), RiskLevel::High);
    assert_eq!(RiskLevel::from_score(0.99), RiskLevel::Critical);
}

#[test]
fn heuristic_risk_level_as_u8() {
    use runtime::heuristic_engine::RiskLevel;
    assert_eq!(RiskLevel::Safe.as_u8(), 0);
    assert_eq!(RiskLevel::Critical.as_u8(), 4);
}

#[test]
fn heuristic_risk_score_safe_default() {
    let s = runtime::heuristic_engine::RiskScore::safe();
    assert_eq!(s.total, 0.0);
    assert_eq!(s.risk_level, runtime::heuristic_engine::RiskLevel::Safe);
}

#[test]
fn heuristic_risk_score_add_contribution() {
    let mut s = runtime::heuristic_engine::RiskScore::safe();
    s.add_contribution("rule1", 0.5, 0.8);
    assert!(s.total > 0.0);
    assert_eq!(s.breakdown.len(), 1);
    assert_eq!(s.triggered_rules.len(), 1);
}

#[test]
fn heuristic_context_scorer_classify() {
    use runtime::heuristic_engine::ContextAwareScorer;
    assert_eq!(ContextAwareScorer::classify_path("cat /etc/shadow"), runtime::heuristic_engine::ContextKind::ConfigSensitive);
    assert_eq!(ContextAwareScorer::classify_path("cat /proc/self/maps"), runtime::heuristic_engine::ContextKind::ProcFs);
    assert_eq!(ContextAwareScorer::classify_path("cat /dev/null"), runtime::heuristic_engine::ContextKind::DeviceFile);
}

#[test]
fn heuristic_context_scorer_destructive() {
    use runtime::heuristic_engine::{ContextAwareScorer, DestructiveLevel};
    use runtime::bash_validation::CommandIntent;
    assert_eq!(
        ContextAwareScorer::classify_destructive("rm -rf /", CommandIntent::Destructive),
        DestructiveLevel::Critical
    );
    assert_eq!(
        ContextAwareScorer::classify_destructive("ls", CommandIntent::ReadOnly),
        DestructiveLevel::Low
    );
}

#[test]
fn heuristic_behavioral_profile() {
    use runtime::heuristic_engine::BehavioralProfile;
    use runtime::bash_validation::CommandIntent;
    let mut p = BehavioralProfile::new();
    assert_eq!(p.total_calls(), 0);
    p.record_call("bash", CommandIntent::ReadOnly, "ls");
    p.record_call("bash", CommandIntent::ReadOnly, "pwd");
    assert_eq!(p.total_calls(), 2);
    assert_eq!(p.tool_frequency("bash"), 2);
}

#[test]
fn heuristic_feedback_loop() {
    use runtime::heuristic_engine::FeedbackLoop;
    let mut f = FeedbackLoop::new();
    for _ in 0..10 { f.record_feedback("rule1", true); }
    let adj = f.adjusted_weight("rule1", 0.5);
    assert!(adj > 0.5);
    assert!(f.is_rule_stable("rule1"));
}

#[test]
fn heuristic_rule_engine_has_rules() {
    use runtime::heuristic_engine::RuleEngine;
    let _re = RuleEngine::new();
    let rules = RuleEngine::default_rules();
    assert!(!rules.is_empty());
}

#[test]
fn heuristic_engine_evaluate() {
    use runtime::heuristic_engine::HeuristicEngine;
    use runtime::bash_validation::CommandIntent;
    use runtime::PermissionMode;
    let mut engine = HeuristicEngine::new();
    let score = engine.evaluate("rm -rf /", "bash", CommandIntent::Destructive, PermissionMode::Allow);
    assert!(score.total > 0.0);
}

#[test]
fn heuristic_engine_disabled_returns_safe() {
    use runtime::heuristic_engine::HeuristicEngine;
    use runtime::bash_validation::CommandIntent;
    use runtime::PermissionMode;
    let mut engine = HeuristicEngine::new();
    engine.enabled = false;
    let score = engine.evaluate("rm -rf /", "bash", CommandIntent::Destructive, PermissionMode::Allow);
    assert_eq!(score.total, 0.0);
}

#[test]
fn size_budget_tool_kind_from_name() {
    use runtime::size_budget::ToolKind;
    assert_eq!(ToolKind::from_name("read_file"), ToolKind::Read);
    assert_eq!(ToolKind::from_name("Read"), ToolKind::Read);
    assert_eq!(ToolKind::from_name("write_file"), ToolKind::Write);
    assert_eq!(ToolKind::from_name("edit_file"), ToolKind::Edit);
    assert_eq!(ToolKind::from_name("glob_search"), ToolKind::Glob);
    assert_eq!(ToolKind::from_name("grep_search"), ToolKind::Grep);
    assert_eq!(ToolKind::from_name("bash"), ToolKind::Bash);
    assert_eq!(ToolKind::from_name("unknown"), ToolKind::Other);
}

#[test]
fn size_budget_tool_budgets() {
    use runtime::size_budget::ToolBudget;
    assert_eq!(ToolBudget::for_read().max_calls, 200);
    assert_eq!(ToolBudget::for_write().max_calls, 100);
    assert_eq!(ToolBudget::for_glob().max_entries, Some(1000));
    assert_eq!(ToolBudget::for_grep().max_calls, 100);
    assert_eq!(ToolBudget::for_bash().max_calls, 100);
    assert_eq!(ToolBudget::for_edit().max_calls, 100);
}

#[test]
fn size_budgeter_normal_usage() {
    use runtime::size_budget::SizeBudgeter;
    let mut b = SizeBudgeter::new();
    assert!(b.check_read(1024).is_ok());
    assert!(b.check_read(4096).is_ok());
}

#[test]
fn size_budgeter_read_exceeds_calls() {
    use runtime::size_budget::SizeBudgeter;
    let mut b = SizeBudgeter::new();
    for _ in 0..200 { b.check_read(1).unwrap(); }
    assert!(b.check_read(1).is_err());
}

#[test]
fn size_budgeter_write_bytes() {
    use runtime::size_budget::SizeBudgeter;
    let mut b = SizeBudgeter::new();
    assert!(b.check_write(2 * 1024 * 1024).is_ok());
    assert!(b.check_write(2 * 1024 * 1024).is_ok());
    assert!(b.check_write(2 * 1024 * 1024).is_err());
}

#[test]
fn size_budgeter_statistics() {
    use runtime::size_budget::SizeBudgeter;
    let mut b = SizeBudgeter::new();
    b.check_read(100).unwrap();
    b.check_write(200).unwrap();
    let s = b.session_statistics();
    assert_eq!(s.total_calls, 2);
    assert_eq!(s.total_bytes, 300);
}

#[test]
fn usage_token_usage_total() {
    let u = runtime::TokenUsage {
        input_tokens: 10,
        output_tokens: 5,
        cache_creation_input_tokens: 2,
        cache_read_input_tokens: 1,
    };
    assert_eq!(u.total_tokens(), 18);
}

#[test]
fn usage_estimate_cost() {
    let u = runtime::TokenUsage {
        input_tokens: 1_000_000,
        output_tokens: 500_000,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    };
    let cost = u.estimate_cost_usd();
    assert_eq!(cost.total_cost_usd(), 52.5);
}

#[test]
fn usage_format_usd() {
    assert!(runtime::format_usd(0.0).starts_with('$'));
    assert!(runtime::format_usd(1.23).starts_with('$'));
}

#[test]
fn usage_pricing_for_model() {
    assert!(runtime::pricing_for_model("claude-haiku").is_some());
    assert!(runtime::pricing_for_model("claude-sonnet").is_some());
    assert!(runtime::pricing_for_model("claude-opus").is_some());
    assert!(runtime::pricing_for_model("unknown-model").is_none());
}

#[test]
fn usage_tracker_cumulative() {
    let mut t = runtime::UsageTracker::new();
    t.record(runtime::TokenUsage { input_tokens: 10, output_tokens: 4, cache_creation_input_tokens: 2, cache_read_input_tokens: 1 });
    t.record(runtime::TokenUsage { input_tokens: 20, output_tokens: 6, cache_creation_input_tokens: 3, cache_read_input_tokens: 2 });
    assert_eq!(t.turns(), 2);
    assert_eq!(t.cumulative_usage().input_tokens, 30);
    assert_eq!(t.cumulative_usage().output_tokens, 10);
    assert_eq!(t.current_turn_usage().input_tokens, 20);
}

#[test]
fn usage_model_specific_cost() {
    let u = runtime::TokenUsage { input_tokens: 1_000_000, output_tokens: 500_000, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
    let haiku = runtime::pricing_for_model("claude-haiku").unwrap();
    let opus = runtime::pricing_for_model("claude-opus").unwrap();
    assert!(u.estimate_cost_usd_with_pricing(haiku).total_cost_usd() < u.estimate_cost_usd_with_pricing(opus).total_cost_usd());
}

#[test]
fn usage_summary_lines() {
    let u = runtime::TokenUsage { input_tokens: 100, output_tokens: 50, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
    let lines = u.summary_lines("test");
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("test:"));
}

#[test]
fn recovery_recipe_for_all_scenarios() {
    for scenario in runtime::recovery_recipes::FailureScenario::all() {
        let recipe = runtime::recovery_recipes::recipe_for(scenario);
        assert!(!recipe.steps.is_empty());
        assert!(recipe.max_attempts >= 1);
    }
}

#[test]
fn recovery_attempt_succeeds() {
    let mut ctx = runtime::recovery_recipes::RecoveryContext::new();
    let scenario = runtime::recovery_recipes::FailureScenario::TrustPromptUnresolved;
    let r = runtime::recovery_recipes::attempt_recovery(&scenario, &mut ctx);
    assert!(matches!(r, runtime::recovery_recipes::RecoveryResult::Recovered { .. }));
}

#[test]
fn recovery_escalation_after_max() {
    let mut ctx = runtime::recovery_recipes::RecoveryContext::new();
    let s = runtime::recovery_recipes::FailureScenario::TrustPromptUnresolved;
    runtime::recovery_recipes::attempt_recovery(&s, &mut ctx);
    let r = runtime::recovery_recipes::attempt_recovery(&s, &mut ctx);
    assert!(matches!(r, runtime::recovery_recipes::RecoveryResult::EscalationRequired { .. }));
}

#[test]
fn recovery_partial_failure() {
    let mut ctx = runtime::recovery_recipes::RecoveryContext::new().with_fail_at_step(1);
    let r = runtime::recovery_recipes::attempt_recovery(
        &runtime::recovery_recipes::FailureScenario::PartialPluginStartup, &mut ctx);
    match r {
        runtime::recovery_recipes::RecoveryResult::PartialRecovery { recovered, remaining } => {
            assert_eq!(recovered.len(), 1);
            assert_eq!(remaining.len(), 1);
        }
        other => panic!("expected PartialRecovery, got {other:?}"),
    }
}

#[test]
fn recovery_first_step_failure_escalates() {
    let mut ctx = runtime::recovery_recipes::RecoveryContext::new().with_fail_at_step(0);
    let r = runtime::recovery_recipes::attempt_recovery(
        &runtime::recovery_recipes::FailureScenario::CompileRedCrossCrate, &mut ctx);
    assert!(matches!(r, runtime::recovery_recipes::RecoveryResult::EscalationRequired { .. }));
}

#[test]
fn recovery_scenario_display() {
    use runtime::recovery_recipes::FailureScenario;
    assert_eq!(FailureScenario::StaleBranch.to_string(), "stale_branch");
    assert_eq!(FailureScenario::ProviderFailure.to_string(), "provider_failure");
    assert_eq!(FailureScenario::McpHandshakeFailure.to_string(), "mcp_handshake_failure");
}

#[test]
fn recovery_context_attempt_count() {
    let mut ctx = runtime::recovery_recipes::RecoveryContext::new();
    let s = runtime::recovery_recipes::FailureScenario::StaleBranch;
    assert_eq!(ctx.attempt_count(&s), 0);
    runtime::recovery_recipes::attempt_recovery(&s, &mut ctx);
    assert_eq!(ctx.attempt_count(&s), 1);
}

#[test]
fn recovery_events_emitted() {
    let mut ctx = runtime::recovery_recipes::RecoveryContext::new();
    let s = runtime::recovery_recipes::FailureScenario::McpHandshakeFailure;
    runtime::recovery_recipes::attempt_recovery(&s, &mut ctx);
    assert!(!ctx.events().is_empty());
}

#[test]
fn stale_branch_recipe_steps() {
    let recipe = runtime::recovery_recipes::recipe_for(&runtime::recovery_recipes::FailureScenario::StaleBranch);
    assert_eq!(recipe.steps.len(), 2);
}

#[test]
fn mcp_handshake_uses_abort_policy() {
    let recipe = runtime::recovery_recipes::recipe_for(&runtime::recovery_recipes::FailureScenario::McpHandshakeFailure);
    assert_eq!(recipe.escalation_policy, runtime::recovery_recipes::EscalationPolicy::Abort);
}

#[test]
fn self_healing_checkpointer_basic() {
    let dir = std::env::temp_dir().join(format!("sh-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cp = runtime::self_healing::SessionCheckpointer::new(&dir, "test-sess");
    assert_eq!(cp.session_id(), "test-sess");
    let input = serde_json::json!({"cmd": "ls"});
    assert!(cp.record_tool_call("bash", &input).is_none());
    let m = cp.checkpoint_now(None);
    assert!(m.is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_checkpointer_find_latest() {
    let dir = std::env::temp_dir().join(format!("sh-find-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cp = runtime::self_healing::SessionCheckpointer::new(&dir, "find");
    cp.checkpoint_now(Some(serde_json::json!({"seq": 1})));
    cp.checkpoint_now(Some(serde_json::json!({"seq": 2})));
    cp.checkpoint_now(Some(serde_json::json!({"seq": 3})));
    let found = runtime::self_healing::SessionCheckpointer::find_latest_checkpoint(&dir);
    assert!(found.is_some());
    assert_eq!(found.unwrap().last_sequence, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_checkpointer_intervals() {
    let dir = std::env::temp_dir().join(format!("sh-int-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cp = runtime::self_healing::SessionCheckpointer::new(&dir, "int")
        .with_intervals(3, 3600);
    let input = serde_json::json!({"cmd": "test"});
    assert!(cp.record_tool_call("bash", &input).is_none());
    assert!(cp.record_tool_call("bash", &input).is_none());
    assert!(cp.record_tool_call("bash", &input).is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_health_monitor() {
    let m = runtime::self_healing::HealthMonitor::new();
    m.register_component("svc");
    assert_eq!(m.component_health("svc"), runtime::self_healing::ComponentHealth::Unknown);
    m.report_heartbeat("svc");
    assert_eq!(m.component_health("svc"), runtime::self_healing::ComponentHealth::Healthy);
    m.report_failure("svc", "err");
    assert_eq!(m.component_health("svc"), runtime::self_healing::ComponentHealth::Unhealthy);
}

#[test]
fn self_healing_health_report() {
    let m = runtime::self_healing::HealthMonitor::new();
    m.register_component("a");
    m.register_component("b");
    m.report_heartbeat("a");
    m.report_failure("b", "crash");
    let r = m.report();
    assert!(!r.all_healthy);
    assert_eq!(r.unhealthy_count, 1);
}

#[test]
fn self_healing_backoff() {
    let mut c = runtime::self_healing::RestartableComponent::new("t");
    assert_eq!(c.attempt, 0);
    c.record_attempt();
    assert_eq!(c.attempt, 1);
    c.reset();
    assert_eq!(c.attempt, 0);
}

#[test]
fn self_healing_escalation() {
    let mut c = runtime::self_healing::RestartableComponent::new("t");
    c.max_attempts = 3;
    assert!(!c.should_escalate());
    c.record_attempt();
    c.record_attempt();
    c.record_attempt();
    assert!(c.should_escalate());
}

#[test]
fn self_healing_auto_restarter() {
    let r = runtime::self_healing::AutoRestarter::new();
    r.register("svc");
    assert_eq!(r.attempt_count("svc"), 0);
    r.record_attempt("svc");
    assert_eq!(r.attempt_count("svc"), 1);
    r.mark_recovered("svc");
    assert_eq!(r.attempt_count("svc"), 0);
}

#[test]
fn self_healing_corruption_repair_fresh() {
    let dir = std::env::temp_dir().join(format!("sh-repair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    assert_eq!(runtime::self_healing::CorruptionRepair::repair(&dir), runtime::self_healing::RepairResult::FreshSession);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_corruption_verify() {
    let dir = std::env::temp_dir().join(format!("sh-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ok.json"), r#"{"ok":true}"#).unwrap();
    std::fs::write(dir.join("bad.json"), r"{bad").unwrap();
    let c = runtime::self_healing::CorruptionRepair::verify_all(&dir);
    assert_eq!(c.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_system_metrics() {
    let m = runtime::self_healing::HealthMonitor::new();
    let metrics = m.collect_metrics();
    assert!(metrics.timestamp_ms > 0);
}

#[test]
fn self_healing_orchestrator() {
    let dir = std::env::temp_dir().join(format!("sh-orch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let orch = runtime::self_healing::SelfHealingOrchestrator::new(&dir);
    orch.start();
    orch.heartbeat("runtime");
    let report = orch.health_report();
    assert!(!report.components.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_shutdown() {
    let dir = std::env::temp_dir().join(format!("sh-shut-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut orch = runtime::self_healing::SelfHealingOrchestrator::new(&dir);
    orch.init_session("s");
    let r = orch.shutdown("test");
    assert!(r.success);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_metrics_critical() {
    let m = runtime::self_healing::SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 100,
        memory_total_kb: 10000,
        disk_free_kb: 0,
        disk_total_kb: 0,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(m.is_memory_critical());

    let m2 = runtime::self_healing::SystemMetrics {
        memory_available_kb: 1000,
        memory_total_kb: 10000,
        disk_free_kb: 100,
        disk_total_kb: 10000,
        ..m
    };
    assert!(!m2.is_memory_critical());
    assert!(m2.is_disk_critical());
}

#[test]
fn self_healing_wal_serialize() {
    let entries = [runtime::self_healing::WalEntry { sequence: 1, timestamp_ms: 1000, operation: "op1".into(), data: serde_json::json!({}) },
        runtime::self_healing::WalEntry { sequence: 2, timestamp_ms: 2000, operation: "op2".into(), data: serde_json::json!({}) }];
    let json = serde_json::to_string(&entries[0]).unwrap();
    assert!(json.contains("op1"));
}

#[test]
fn global_concurrency_manager() {
    let m = runtime::concurrency::global_concurrency_manager();
    assert_eq!(m.limit(runtime::concurrency::ConcurrencyCategory::Bash), 5);
}

#[test]
fn global_rate_limiter_exists() {
    let limiter = runtime::rate_limiter::global_rate_limiter();
    let mut guard = limiter.lock().unwrap();
    assert!(guard.get_mut("anthropic").is_some());
}

#[test]
fn global_health_registry_exists() {
    let r = runtime::health_probe::global_health_registry();
    let guard = r.lock().unwrap();
    assert!(guard.get("anthropic").is_some());
}

#[test]
fn global_circuit_forest_exists() {
    let f = runtime::circuit_breaker::global_circuit_forest();
    let guard = f.lock().unwrap();
    assert!(guard.get("global").is_some());
}

#[test]
fn validate_path_safety_null_byte() {
    let r = runtime::path_traversal::validate_path_safety(
        Path::new("file\u{0}.txt"), Path::new("/workspace"));
    assert!(r.is_err());
}

#[test]
fn validate_path_safety_device() {
    let r = runtime::path_traversal::validate_path_safety(
        Path::new("/dev/sda"), Path::new("/workspace"));
    assert!(r.is_err());
}

// =====================================================================
// bash_validation
// =====================================================================

#[test]
fn bash_read_only_allows_cat() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("cat src/main.rs", PermissionMode::ReadOnly);
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_read_only_blocks_rm() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("rm file.txt", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_read_only_blocks_cp() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("cp a.txt b.txt", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_read_only_blocks_redirection() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("echo hi > file.txt", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_read_only_allows_in_non_readonly() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("rm file.txt", PermissionMode::Allow);
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_read_only_blocks_sudo_rm() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("sudo rm /etc/config", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_read_only_allows_git_log() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("git log --oneline", PermissionMode::ReadOnly);
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_read_only_blocks_git_push() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("git push origin main", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_read_only_blocks_apt_install() {
    use runtime::bash_validation::validate_read_only;
    use runtime::PermissionMode;
    let r = validate_read_only("apt install curl", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_destructive_rm_rf_root() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive("rm -rf /");
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_destructive_rm_rf_home() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive("rm -rf ~");
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_destructive_mkfs() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive("mkfs.ext4 /dev/sda1");
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_destructive_shred() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive("shred file.txt");
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_destructive_fork_bomb() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive(":(){ :|:& };:");
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_destructive_clean_command() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive("cat file.txt");
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_destructive_rm_rf_generic() {
    use runtime::bash_validation::check_destructive;
    let r = check_destructive("rm -r -f tmp/build");
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_mode_readonly_blocks() {
    use runtime::bash_validation::validate_mode;
    use runtime::PermissionMode;
    let r = validate_mode("rm file.txt", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_mode_workspace_warns_outside() {
    use runtime::bash_validation::validate_mode;
    use runtime::PermissionMode;
    let r = validate_mode("cp /etc/passwd .", PermissionMode::WorkspaceWrite);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_mode_full_access_allows() {
    use runtime::bash_validation::validate_mode;
    use runtime::PermissionMode;
    let r = validate_mode("rm -rf /", PermissionMode::DangerFullAccess);
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_sed_blocks_in_readonly() {
    use runtime::bash_validation::validate_sed;
    use runtime::PermissionMode;
    let r = validate_sed("sed -i 's/foo/bar/' file.txt", PermissionMode::ReadOnly);
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Block { .. }));
}

#[test]
fn bash_sed_allows_non_readonly() {
    use runtime::bash_validation::validate_sed;
    use runtime::PermissionMode;
    let r = validate_sed("sed -i 's/foo/bar/' file.txt", PermissionMode::Allow);
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_sed_non_inplace_allowed() {
    use runtime::bash_validation::validate_sed;
    use runtime::PermissionMode;
    let r = validate_sed("sed 's/foo/bar/' file.txt", PermissionMode::ReadOnly);
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_path_traversal_warns() {
    use runtime::bash_validation::validate_paths;
    let r = validate_paths("cat ../../etc/passwd", Path::new("/workspace"));
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_path_home_warns() {
    use runtime::bash_validation::validate_paths;
    let r = validate_paths("cat ~/.ssh/id_rsa", Path::new("/workspace"));
    assert!(matches!(r, runtime::bash_validation::ValidationResult::Warn { .. }));
}

#[test]
fn bash_path_clean_allows() {
    use runtime::bash_validation::validate_paths;
    let r = validate_paths("cat src/main.rs", Path::new("/workspace"));
    assert_eq!(r, runtime::bash_validation::ValidationResult::Allow);
}

#[test]
fn bash_classify_readonly() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("ls -la"), CommandIntent::ReadOnly);
    assert_eq!(classify_command("cat file.txt"), CommandIntent::ReadOnly);
    assert_eq!(classify_command("grep pattern ."), CommandIntent::ReadOnly);
}

#[test]
fn bash_classify_write() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("cp a.txt b.txt"), CommandIntent::Write);
    assert_eq!(classify_command("mkdir newdir"), CommandIntent::Write);
    assert_eq!(classify_command("touch file.txt"), CommandIntent::Write);
}

#[test]
fn bash_classify_destructive() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("rm file.txt"), CommandIntent::Destructive);
    assert_eq!(classify_command("shred file.txt"), CommandIntent::Destructive);
}

#[test]
fn bash_classify_network() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("curl https://example.com"), CommandIntent::Network);
    assert_eq!(classify_command("wget https://example.com/file"), CommandIntent::Network);
}

#[test]
fn bash_classify_package() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("npm install express"), CommandIntent::PackageManagement);
    assert_eq!(classify_command("pip install requests"), CommandIntent::PackageManagement);
}

#[test]
fn bash_classify_git_readonly() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("git log"), CommandIntent::ReadOnly);
    assert_eq!(classify_command("git diff"), CommandIntent::ReadOnly);
    assert_eq!(classify_command("git status"), CommandIntent::ReadOnly);
}

#[test]
fn bash_classify_git_write() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("git commit -m msg"), CommandIntent::Write);
    assert_eq!(classify_command("git push"), CommandIntent::Write);
}

#[test]
fn bash_classify_unknown() {
    use runtime::bash_validation::{classify_command, CommandIntent};
    assert_eq!(classify_command("my_custom_tool --flag"), CommandIntent::Unknown);
}

#[test]
fn bash_detailed_file_read() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("cat src/main.rs"), DetailedIntent::FileRead);
    assert_eq!(classify_detailed("head -20 file.txt"), DetailedIntent::FileRead);
}

#[test]
fn bash_detailed_file_search() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("grep -r pattern ."), DetailedIntent::FileSearch);
    assert_eq!(classify_detailed("find . -name '*.rs'"), DetailedIntent::FileSearch);
}

#[test]
fn bash_detailed_file_write() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("cp a.txt b.txt"), DetailedIntent::FileWrite);
    assert_eq!(classify_detailed("mkdir newdir"), DetailedIntent::FileWrite);
}

#[test]
fn bash_detailed_destructive() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("rm file.txt"), DetailedIntent::Destructive);
    assert_eq!(classify_detailed("shred file.txt"), DetailedIntent::Destructive);
}

#[test]
fn bash_detailed_network_download() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("curl https://example.com"), DetailedIntent::NetworkDownload);
}

#[test]
fn bash_detailed_network_shell() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("ssh user@host"), DetailedIntent::NetworkShell);
}

#[test]
fn bash_detailed_compress() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("tar -xzf archive.tar.gz"), DetailedIntent::Compress);
    assert_eq!(classify_detailed("zip archive.zip file.txt"), DetailedIntent::Compress);
}

#[test]
fn bash_detailed_container() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("docker ps"), DetailedIntent::Container);
}

#[test]
fn bash_detailed_database() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("psql -d mydb"), DetailedIntent::Database);
}

#[test]
fn bash_detailed_permission_change() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("chmod 755 script.sh"), DetailedIntent::PermissionChange);
    assert_eq!(classify_detailed("chown user:group file"), DetailedIntent::PermissionChange);
}

#[test]
fn bash_detailed_sed_readonly() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("sed 's/foo/bar/' file"), DetailedIntent::FileRead);
}

#[test]
fn bash_detailed_sed_inplace() {
    use runtime::bash_validation::{classify_detailed, DetailedIntent};
    assert_eq!(classify_detailed("sed -i 's/foo/bar/' file"), DetailedIntent::FileEdit);
}

// =====================================================================
// config_validate
// =====================================================================

#[test]
fn config_unsupported_toml() {
    let r = runtime::config_validate::check_unsupported_format(Path::new("config.toml"));
    assert!(r.is_err());
}

#[test]
fn config_unsupported_json_ok() {
    let r = runtime::config_validate::check_unsupported_format(Path::new("settings.json"));
    assert!(r.is_ok());
}

#[test]
fn config_unsupported_yaml_ok() {
    let r = runtime::config_validate::check_unsupported_format(Path::new("config.yaml"));
    assert!(r.is_ok());
}

#[test]
fn config_diagnostic_display_unknown_key() {
    let diag = runtime::config_validate::ConfigDiagnostic {
        path: "test.json".to_string(),
        field: "foo".to_string(),
        line: None,
        kind: runtime::config_validate::DiagnosticKind::UnknownKey { suggestion: None },
    };
    let s = format!("{diag}");
    assert!(s.contains("unknown key"));
}

#[test]
fn config_diagnostic_display_with_suggestion() {
    let diag = runtime::config_validate::ConfigDiagnostic {
        path: "test.json".to_string(),
        field: "modle".to_string(),
        line: None,
        kind: runtime::config_validate::DiagnosticKind::UnknownKey {
            suggestion: Some("model".to_string()),
        },
    };
    let s = format!("{diag}");
    assert!(s.contains("model"));
}

#[test]
fn config_diagnostic_display_wrong_type() {
    let diag = runtime::config_validate::ConfigDiagnostic {
        path: "test.json".to_string(),
        field: "model".to_string(),
        line: Some(5),
        kind: runtime::config_validate::DiagnosticKind::WrongType {
            expected: "a string",
            got: "a boolean",
        },
    };
    let s = format!("{diag}");
    assert!(s.contains("line 5"));
    assert!(s.contains("a string"));
}

#[test]
fn config_diagnostic_display_deprecated() {
    let diag = runtime::config_validate::ConfigDiagnostic {
        path: "test.json".to_string(),
        field: "oldKey".to_string(),
        line: None,
        kind: runtime::config_validate::DiagnosticKind::Deprecated {
            replacement: "newKey",
        },
    };
    let s = format!("{diag}");
    assert!(s.contains("deprecated"));
    assert!(s.contains("newKey"));
}

#[test]
fn config_validation_result_is_ok_empty() {
    let result = runtime::config_validate::ValidationResult {
        errors: Vec::new(),
        warnings: Vec::new(),
    };
    assert!(result.is_ok());
}

#[test]
fn config_validation_result_not_ok_with_errors() {
    let result = runtime::config_validate::ValidationResult {
        errors: vec![runtime::config_validate::ConfigDiagnostic {
            path: "test.json".to_string(),
            field: "bad".to_string(),
            line: None,
            kind: runtime::config_validate::DiagnosticKind::UnknownKey { suggestion: None },
        }],
        warnings: Vec::new(),
    };
    assert!(!result.is_ok());
}

#[test]
fn config_format_diagnostics_empty() {
    let result = runtime::config_validate::ValidationResult {
        errors: Vec::new(),
        warnings: Vec::new(),
    };
    let formatted = runtime::config_validate::format_diagnostics(&result);
    assert!(formatted.is_empty());
}

#[test]
fn config_format_diagnostics_with_warnings() {
    let result = runtime::config_validate::ValidationResult {
        errors: Vec::new(),
        warnings: vec![runtime::config_validate::ConfigDiagnostic {
            path: "test.json".to_string(),
            field: "oldKey".to_string(),
            line: None,
            kind: runtime::config_validate::DiagnosticKind::Deprecated {
                replacement: "newKey",
            },
        }],
    };
    let formatted = runtime::config_validate::format_diagnostics(&result);
    assert!(formatted.contains("warning:"));
}

#[test]
fn config_format_diagnostics_with_errors() {
    let result = runtime::config_validate::ValidationResult {
        errors: vec![runtime::config_validate::ConfigDiagnostic {
            path: "test.json".to_string(),
            field: "foo".to_string(),
            line: None,
            kind: runtime::config_validate::DiagnosticKind::UnknownKey { suggestion: None },
        }],
        warnings: Vec::new(),
    };
    let formatted = runtime::config_validate::format_diagnostics(&result);
    assert!(formatted.contains("error:"));
}

// =====================================================================
// audit_integration
// =====================================================================

#[test]
fn audit_create_session() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    assert_eq!(a.session_id(), "audit-test");
    assert!(a.verify_chain());
}

#[test]
fn audit_record_tool_call() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    a.record_tool_call("bash", true);
    assert_eq!(a.tool_call_count(), 1);
    assert!(a.verify_chain());
}

#[test]
fn audit_record_permission() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    a.record_permission(true, "file:/tmp/test");
    a.record_permission(false, "file:/etc/secret");
    assert!(a.verify_chain());
}

#[test]
fn audit_end_session() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    a.end_session();
    assert!(a.verify_chain());
}

#[test]
fn audit_integrity_ok() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    assert!(a.verify_integrity().is_ok());
}

#[test]
fn audit_without_signing() {
    let a = runtime::audit_integration::SessionAuditor::new_without_signing("audit-no-sign");
    assert!(a.signing_key().is_none());
    assert!(a.verifying_key().is_none());
    assert!(a.verify_chain());
}

#[test]
fn audit_uptime() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    assert_eq!(a.uptime_secs(), 0);
}

#[test]
fn audit_tool_call_count_multiple() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    a.record_tool_call("bash", true);
    a.record_tool_call("read_file", true);
    a.record_tool_call("write_file", false);
    assert_eq!(a.tool_call_count(), 3);
    assert!(a.verify_chain());
}

#[test]
fn audit_log_ref() {
    let a = runtime::audit_integration::SessionAuditor::new("audit-test");
    let log = a.log_ref();
    let guard = log.lock().unwrap();
    assert!(!guard.is_empty());
}

// =====================================================================
// branch_lock
// =====================================================================

#[test]
fn branch_lock_no_collisions() {
    use runtime::branch_lock::{detect_branch_lock_collisions, BranchLockIntent};
    let intents = vec![
        BranchLockIntent {
            lane_id: "lane-a".to_string(),
            branch: "feature/a".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
        BranchLockIntent {
            lane_id: "lane-b".to_string(),
            branch: "feature/b".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
    ];
    let collisions = detect_branch_lock_collisions(&intents);
    assert!(collisions.is_empty());
}

#[test]
fn branch_lock_same_branch_same_module() {
    use runtime::branch_lock::{detect_branch_lock_collisions, BranchLockIntent};
    let intents = vec![
        BranchLockIntent {
            lane_id: "lane-a".to_string(),
            branch: "feature/lock".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
        BranchLockIntent {
            lane_id: "lane-b".to_string(),
            branch: "feature/lock".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
    ];
    let collisions = detect_branch_lock_collisions(&intents);
    assert_eq!(collisions.len(), 1);
    assert_eq!(collisions[0].branch, "feature/lock");
    assert_eq!(collisions[0].module, "runtime/mcp");
    assert_eq!(collisions[0].lane_ids, vec!["lane-a", "lane-b"]);
}

#[test]
fn branch_lock_submodule_overlap() {
    use runtime::branch_lock::{detect_branch_lock_collisions, BranchLockIntent};
    let intents = vec![
        BranchLockIntent {
            lane_id: "lane-a".to_string(),
            branch: "feature/x".to_string(),
            worktree: None,
            modules: vec!["runtime".to_string()],
        },
        BranchLockIntent {
            lane_id: "lane-b".to_string(),
            branch: "feature/x".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
    ];
    let collisions = detect_branch_lock_collisions(&intents);
    assert_eq!(collisions.len(), 1);
    assert_eq!(collisions[0].module, "runtime");
}

#[test]
fn branch_lock_empty_intents() {
    use runtime::branch_lock::detect_branch_lock_collisions;
    let collisions = detect_branch_lock_collisions(&[]);
    assert!(collisions.is_empty());
}

#[test]
fn branch_lock_three_way_collision() {
    use runtime::branch_lock::{detect_branch_lock_collisions, BranchLockIntent};
    let intents = vec![
        BranchLockIntent {
            lane_id: "lane-a".to_string(),
            branch: "feature/y".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
        BranchLockIntent {
            lane_id: "lane-b".to_string(),
            branch: "feature/y".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
        BranchLockIntent {
            lane_id: "lane-c".to_string(),
            branch: "feature/y".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string()],
        },
    ];
    let collisions = detect_branch_lock_collisions(&intents);
    assert_eq!(collisions.len(), 3);
}

#[test]
fn branch_lock_multiple_modules_collision() {
    use runtime::branch_lock::{detect_branch_lock_collisions, BranchLockIntent};
    let intents = vec![
        BranchLockIntent {
            lane_id: "lane-a".to_string(),
            branch: "feature/z".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string(), "runtime/bash".to_string()],
        },
        BranchLockIntent {
            lane_id: "lane-b".to_string(),
            branch: "feature/z".to_string(),
            worktree: None,
            modules: vec!["runtime/mcp".to_string(), "runtime/bash".to_string()],
        },
    ];
    let collisions = detect_branch_lock_collisions(&intents);
    assert_eq!(collisions.len(), 2);
}
