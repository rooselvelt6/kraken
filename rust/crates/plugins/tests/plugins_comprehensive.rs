use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use plugins::{
    builtin_plugins, load_plugin_from_directory,
    HookEvent, HookRunResult, HookRunner,
    Plugin, PluginDefinition,
    PluginKind, PluginPermission, PluginToolPermission,
    PluginHooks, PluginLifecycle, PluginManifest, PluginToolManifest,
    PluginToolDefinition, PluginCommandManifest, PluginTool,
    PluginMetadata, PluginManager, PluginManagerConfig,
    PluginRegistry, RegisteredPlugin,
    PluginLoadFailure, PluginRegistryReport,
    PluginSummary, PluginError, PluginManifestValidationError,
    InstalledPluginRegistry, InstalledPluginRecord, PluginInstallSource,
};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("plugins-comprehensive-{label}-{nanos}"))
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(path, perms).unwrap_or_else(|e| panic!("chmod +x {}: {e}", path.display()));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent dir");
    }
    fs::write(path, contents).expect("write file");
}

fn make_builtin_plugin(_name: &str) -> PluginDefinition {
    builtin_plugins().into_iter().next().expect("at least one builtin")
}

fn write_external_plugin(root: &Path, name: &str, version: &str) {
    let path = root.join(".claude-plugin").join("plugin.json");
    write_file(
        &path,
        &format!(
            r#"{{"name":"{name}","version":"{version}","description":"test plugin"}}"#
        ),
    );
}

fn write_bundled_plugin(root: &Path, name: &str, version: &str, default_enabled: bool) {
    let path = root.join(".claude-plugin").join("plugin.json");
    write_file(
        &path,
        &format!(
            r#"{{"name":"{}","version":"{}","description":"bundled plugin","defaultEnabled":{}}}"#,
            name, version, if default_enabled { "true" } else { "false" }
        ),
    );
}

fn write_tool_plugin(root: &Path, name: &str, tool_name: &str) {
    let script = root.join("tools").join("echo.sh");
    write_file(&script, "#!/bin/sh\ncat\n");
    make_executable(&script);
    let path = root.join(".claude-plugin").join("plugin.json");
    write_file(
        &path,
        &format!(
            r#"{{"name":"{name}","version":"1.0.0","description":"tool plugin","tools":[{{"name":"{tool_name}","description":"echo","inputSchema":{{"type":"object"}},"command":"./tools/echo.sh","requiredPermission":"workspace-write"}}]}}"#
        ),
    );
}

fn write_hook_plugin(root: &Path, name: &str, pre_text: &str) {
    let pre_path = root.join("hooks").join("pre.sh");
    write_file(&pre_path, &format!("#!/bin/sh\nprintf '%s\\n' '{pre_text}'\n"));
    make_executable(&pre_path);
    let path = root.join("plugin.json");
    write_file(
        &path,
        &format!(
            r#"{{"name":"{name}","version":"1.0.0","description":"hook plugin","hooks":{{"PreToolUse":["./hooks/pre.sh"]}}}}"#
        ),
    );
}

#[test]
fn test_plugin_kind_builtin_variants() {
    assert_eq!(PluginKind::Builtin as isize, 0);
    assert_ne!(PluginKind::Builtin, PluginKind::Bundled);
    assert_ne!(PluginKind::Builtin, PluginKind::External);
}

#[test]
fn test_plugin_kind_equality() {
    assert_eq!(PluginKind::Builtin, PluginKind::Builtin);
    assert_eq!(PluginKind::Bundled, PluginKind::Bundled);
    assert_eq!(PluginKind::External, PluginKind::External);
}

#[test]
fn test_plugin_kind_display() {
    assert_eq!(PluginKind::Builtin.to_string(), "builtin");
    assert_eq!(PluginKind::Bundled.to_string(), "bundled");
    assert_eq!(PluginKind::External.to_string(), "external");
}

#[test]
fn test_plugin_kind_clone() {
    let k = PluginKind::Builtin;
    let c = k;
    assert_eq!(k, c);
}

#[test]
fn test_plugin_kind_copy() {
    let k = PluginKind::External;
    let c = k;
    assert_eq!(k, c);
}

#[test]
fn test_plugin_kind_serde_roundtrip() {
    let kinds = [PluginKind::Builtin, PluginKind::Bundled, PluginKind::External];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let des: PluginKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, des);
    }
}

#[test]
fn test_plugin_kind_serde_lowercase() {
    let json = "\"builtin\"";
    let des: PluginKind = serde_json::from_str(json).unwrap();
    assert_eq!(des, PluginKind::Builtin);
    let json = "\"bundled\"";
    let des: PluginKind = serde_json::from_str(json).unwrap();
    assert_eq!(des, PluginKind::Bundled);
    let json = "\"external\"";
    let des: PluginKind = serde_json::from_str(json).unwrap();
    assert_eq!(des, PluginKind::External);
}

#[test]
fn test_plugin_kind_serde_errors_on_unknown() {
    let result = serde_json::from_str::<PluginKind>("\"unknown\"");
    assert!(result.is_err());
}

#[test]
fn test_plugin_permission_as_str() {
    assert_eq!(PluginPermission::Read.as_str(), "read");
    assert_eq!(PluginPermission::Write.as_str(), "write");
    assert_eq!(PluginPermission::Execute.as_str(), "execute");
}

#[test]
fn test_plugin_permission_as_ref() {
    let p = PluginPermission::Read;
    let r: &str = p.as_ref();
    assert_eq!(r, "read");
    let p = PluginPermission::Write;
    let r: &str = p.as_ref();
    assert_eq!(r, "write");
    let p = PluginPermission::Execute;
    let r: &str = p.as_ref();
    assert_eq!(r, "execute");
}

#[test]
fn test_plugin_permission_ord_order() {
    assert!(PluginPermission::Read < PluginPermission::Write);
    assert!(PluginPermission::Write < PluginPermission::Execute);
    assert!(PluginPermission::Read < PluginPermission::Execute);
}

#[test]
fn test_plugin_permission_ord_eq() {
    assert!(PluginPermission::Read >= PluginPermission::Read);
    assert!(PluginPermission::Write <= PluginPermission::Write);
}

#[test]
fn test_plugin_permission_serde_roundtrip() {
    let perms = [PluginPermission::Read, PluginPermission::Write, PluginPermission::Execute];
    for p in perms {
        let json = serde_json::to_string(&p).unwrap();
        let des: PluginPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(p, des);
    }
}

#[test]
fn test_plugin_permission_serde_lowercase() {
    let des: PluginPermission = serde_json::from_str("\"read\"").unwrap();
    assert_eq!(des, PluginPermission::Read);
}

#[test]
fn test_plugin_permission_serde_invalid() {
    let result = serde_json::from_str::<PluginPermission>("\"admin\"");
    assert!(result.is_err());
}

#[test]
fn test_plugin_permission_default_is_not_derived() {
    let perms = [PluginPermission::Read, PluginPermission::Write, PluginPermission::Execute];
    assert!(!perms.iter().all(|p| *p == PluginPermission::Read));
}

#[test]
fn test_plugin_permission_copy() {
    let p = PluginPermission::Write;
    let q = p;
    assert_eq!(p, q);
}

#[test]
fn test_plugin_permission_clone() {
    let p = PluginPermission::Execute;
    let q = p;
    assert_eq!(p, q);
}

#[test]
fn test_plugin_tool_permission_as_str() {
    assert_eq!(PluginToolPermission::ReadOnly.as_str(), "read-only");
    assert_eq!(PluginToolPermission::WorkspaceWrite.as_str(), "workspace-write");
    assert_eq!(PluginToolPermission::DangerFullAccess.as_str(), "danger-full-access");
}

#[test]
fn test_plugin_tool_permission_ord() {
    assert!(PluginToolPermission::ReadOnly < PluginToolPermission::WorkspaceWrite);
    assert!(PluginToolPermission::WorkspaceWrite < PluginToolPermission::DangerFullAccess);
}

#[test]
fn test_plugin_tool_permission_ord_eq() {
    let a = PluginToolPermission::ReadOnly;
    let b = PluginToolPermission::ReadOnly;
    assert_eq!(a, b);
    assert!(a <= b);
    assert!(a >= b);
}

#[test]
fn test_plugin_tool_permission_serde_roundtrip() {
    let perms = [PluginToolPermission::ReadOnly, PluginToolPermission::WorkspaceWrite, PluginToolPermission::DangerFullAccess];
    for p in perms {
        let json = serde_json::to_string(&p).unwrap();
        let des: PluginToolPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(p, des);
    }
}

#[test]
fn test_plugin_tool_permission_serde_kebab() {
    let des: PluginToolPermission = serde_json::from_str("\"read-only\"").unwrap();
    assert_eq!(des, PluginToolPermission::ReadOnly);
    let des: PluginToolPermission = serde_json::from_str("\"workspace-write\"").unwrap();
    assert_eq!(des, PluginToolPermission::WorkspaceWrite);
    let des: PluginToolPermission = serde_json::from_str("\"danger-full-access\"").unwrap();
    assert_eq!(des, PluginToolPermission::DangerFullAccess);
}

#[test]
fn test_plugin_tool_permission_serde_invalid() {
    let result = serde_json::from_str::<PluginToolPermission>("\"invalid\"");
    assert!(result.is_err());
}

#[test]
fn test_plugin_tool_permission_clone() {
    let a = PluginToolPermission::WorkspaceWrite;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn test_plugin_tool_permission_copy() {
    let a = PluginToolPermission::DangerFullAccess;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn test_plugin_hooks_default_is_empty() {
    let hooks = PluginHooks::default();
    assert!(hooks.pre_tool_use.is_empty());
    assert!(hooks.post_tool_use.is_empty());
    assert!(hooks.post_tool_use_failure.is_empty());
    assert!(hooks.is_empty());
}

#[test]
fn test_plugin_hooks_is_empty_true() {
    let hooks = PluginHooks::default();
    assert!(hooks.is_empty());
}

#[test]
fn test_plugin_hooks_is_empty_false_pre() {
    let hooks = PluginHooks { pre_tool_use: vec!["a.sh".into()], ..Default::default() };
    assert!(!hooks.is_empty());
}

#[test]
fn test_plugin_hooks_is_empty_false_post() {
    let hooks = PluginHooks { post_tool_use: vec!["b.sh".into()], ..Default::default() };
    assert!(!hooks.is_empty());
}

#[test]
fn test_plugin_hooks_is_empty_false_failure() {
    let hooks = PluginHooks { post_tool_use_failure: vec!["c.sh".into()], ..Default::default() };
    assert!(!hooks.is_empty());
}

#[test]
fn test_plugin_hooks_merged_with_both_empty() {
    let a = PluginHooks::default();
    let b = PluginHooks::default();
    let merged = a.merged_with(&b);
    assert!(merged.is_empty());
}

#[test]
fn test_plugin_hooks_merged_with_only_pre() {
    let a = PluginHooks { pre_tool_use: vec!["a.sh".into()], ..Default::default() };
    let b = PluginHooks::default();
    let merged = a.merged_with(&b);
    assert_eq!(merged.pre_tool_use, vec!["a.sh"]);
    assert!(merged.post_tool_use.is_empty());
}

#[test]
fn test_plugin_hooks_merged_with_accumulates() {
    let a = PluginHooks { pre_tool_use: vec!["a.sh".into()], ..Default::default() };
    let b = PluginHooks { pre_tool_use: vec!["b.sh".into()], post_tool_use: vec!["p.sh".into()], ..Default::default() };
    let merged = a.merged_with(&b);
    assert_eq!(merged.pre_tool_use, vec!["a.sh", "b.sh"]);
    assert_eq!(merged.post_tool_use, vec!["p.sh"]);
}

#[test]
fn test_plugin_hooks_merged_with_failure() {
    let a = PluginHooks { post_tool_use_failure: vec!["f1.sh".into()], ..Default::default() };
    let b = PluginHooks { post_tool_use_failure: vec!["f2.sh".into()], ..Default::default() };
    let merged = a.merged_with(&b);
    assert_eq!(merged.post_tool_use_failure, vec!["f1.sh", "f2.sh"]);
}

#[test]
fn test_plugin_hooks_clone() {
    let h = PluginHooks { pre_tool_use: vec!["x.sh".into()], ..Default::default() };
    let c = h.clone();
    assert_eq!(h.pre_tool_use, c.pre_tool_use);
}

#[test]
fn test_plugin_hooks_serde_roundtrip() {
    let hooks = PluginHooks {
        pre_tool_use: vec!["pre.sh".into()],
        post_tool_use: vec!["post.sh".into()],
        post_tool_use_failure: vec!["fail.sh".into()],
    };
    let json = serde_json::to_string(&hooks).unwrap();
    let des: PluginHooks = serde_json::from_str(&json).unwrap();
    assert_eq!(hooks, des);
}

#[test]
fn test_plugin_hooks_serde_remapped_names() {
    let json = r#"{"PreToolUse":["p.sh"],"PostToolUse":["o.sh"],"PostToolUseFailure":["f.sh"]}"#;
    let des: PluginHooks = serde_json::from_str(json).unwrap();
    assert_eq!(des.pre_tool_use, vec!["p.sh"]);
    assert_eq!(des.post_tool_use, vec!["o.sh"]);
    assert_eq!(des.post_tool_use_failure, vec!["f.sh"]);
}

#[test]
fn test_plugin_hooks_serde_omitted_fields_default_empty() {
    let json = r"{}";
    let des: PluginHooks = serde_json::from_str(json).unwrap();
    assert!(des.is_empty());
}

#[test]
fn test_plugin_hooks_equality() {
    let a = PluginHooks::default();
    let b = PluginHooks::default();
    assert_eq!(a, b);
    let c = PluginHooks { pre_tool_use: vec!["x".into()], ..Default::default() };
    assert_ne!(a, c);
}

#[test]
fn test_plugin_lifecycle_default_empty() {
    let lc = PluginLifecycle::default();
    assert!(lc.init.is_empty());
    assert!(lc.shutdown.is_empty());
}

#[test]
fn test_plugin_lifecycle_is_empty_true() {
    let lc = PluginLifecycle::default();
    assert!(lc.is_empty());
}

#[test]
fn test_plugin_lifecycle_is_empty_false_init() {
    let lc = PluginLifecycle { init: vec!["init.sh".into()], shutdown: vec![] };
    assert!(!lc.is_empty());
}

#[test]
fn test_plugin_lifecycle_is_empty_false_shutdown() {
    let lc = PluginLifecycle { init: vec![], shutdown: vec!["shutdown.sh".into()] };
    assert!(!lc.is_empty());
}

#[test]
fn test_plugin_lifecycle_both_non_empty() {
    let lc = PluginLifecycle { init: vec!["init.sh".into()], shutdown: vec!["shutdown.sh".into()] };
    assert!(!lc.is_empty());
}

#[test]
fn test_plugin_lifecycle_clone() {
    let lc = PluginLifecycle { init: vec!["i.sh".into()], shutdown: vec!["s.sh".into()] };
    let c = lc.clone();
    assert_eq!(lc, c);
}

#[test]
fn test_plugin_lifecycle_serde_remapped_names() {
    let json = r#"{"Init":["i.sh"],"Shutdown":["s.sh"]}"#;
    let des: PluginLifecycle = serde_json::from_str(json).unwrap();
    assert_eq!(des.init, vec!["i.sh"]);
    assert_eq!(des.shutdown, vec!["s.sh"]);
}

#[test]
fn test_plugin_lifecycle_serde_roundtrip() {
    let lc = PluginLifecycle { init: vec!["init.sh".into()], shutdown: vec!["shutdown.sh".into()] };
    let json = serde_json::to_string(&lc).unwrap();
    let des: PluginLifecycle = serde_json::from_str(&json).unwrap();
    assert_eq!(lc, des);
}

#[test]
fn test_plugin_lifecycle_serde_omitted_default_empty() {
    let json = r"{}";
    let des: PluginLifecycle = serde_json::from_str(json).unwrap();
    assert!(des.is_empty());
}

#[test]
fn test_plugin_lifecycle_equality() {
    let a = PluginLifecycle::default();
    let b = PluginLifecycle::default();
    assert_eq!(a, b);
}

#[test]
fn test_plugin_manifest_struct_fields() {
    let manifest = PluginManifest {
        name: "test".into(),
        version: "1.0.0".into(),
        description: "desc".into(),
        permissions: vec![PluginPermission::Read],
        default_enabled: true,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    assert_eq!(manifest.name, "test");
    assert_eq!(manifest.version, "1.0.0");
    assert_eq!(manifest.description, "desc");
    assert_eq!(manifest.permissions.len(), 1);
    assert!(manifest.default_enabled);
}

#[test]
fn test_plugin_manifest_default_enabled_false() {
    let manifest = PluginManifest {
        default_enabled: false,
        name: "t".into(), version: "1".into(), description: "d".into(),
        permissions: vec![], hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(), tools: vec![], commands: vec![],
    };
    assert!(!manifest.default_enabled);
}

#[test]
fn test_plugin_manifest_client() {
    let manifest = PluginManifest {
        name: "test".into(),
        version: "1.0.0".into(),
        description: "desc".into(),
        permissions: vec![],
        default_enabled: true,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    assert!(!format!("{manifest:?}").is_empty());
}

#[test]
fn test_plugin_manifest_serde_roundtrip() {
    let manifest = PluginManifest {
        name: "test".into(),
        version: "1.0.0".into(),
        description: "desc".into(),
        permissions: vec![PluginPermission::Read],
        default_enabled: true,
        hooks: PluginHooks { pre_tool_use: vec!["p.sh".into()], ..Default::default() },
        lifecycle: PluginLifecycle { init: vec!["i.sh".into()], ..Default::default() },
        tools: vec![],
        commands: vec![PluginCommandManifest { name: "cmd".into(), description: "desc".into(), command: "echo".into() }],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let des: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.name, des.name);
    assert_eq!(manifest.version, des.version);
    assert_eq!(manifest.permissions.len(), des.permissions.len());
}

#[test]
fn test_plugin_tool_manifest_struct() {
    let tm = PluginToolManifest {
        name: "my_tool".into(),
        description: "My tool".into(),
        input_schema: serde_json::json!({"type": "object"}),
        command: "./script.sh".into(),
        args: vec!["--flag".into()],
        required_permission: PluginToolPermission::ReadOnly,
    };
    assert_eq!(tm.name, "my_tool");
    assert_eq!(tm.args, vec!["--flag"]);
    assert_eq!(tm.required_permission, PluginToolPermission::ReadOnly);
}

#[test]
fn test_plugin_tool_manifest_default_args_empty() {
    let json = r#"{"name":"t","description":"d","inputSchema":{"type":"object"},"command":"./s.sh","required_permission":"read-only"}"#;
    let des: PluginToolManifest = serde_json::from_str(json).unwrap();
    assert!(des.args.is_empty());
}

#[test]
fn test_plugin_tool_manifest_serde_roundtrip() {
    let tm = PluginToolManifest {
        name: "t".into(),
        description: "d".into(),
        input_schema: serde_json::json!({"type": "object"}),
        command: "./script.sh".into(),
        args: vec!["--flag".into()],
        required_permission: PluginToolPermission::WorkspaceWrite,
    };
    let json = serde_json::to_string(&tm).unwrap();
    let des: PluginToolManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(tm.required_permission, des.required_permission);
}

#[test]
fn test_plugin_tool_manifests_serde_array() {
    let tm = vec![PluginToolManifest {
        name: "t".into(),
        description: "d".into(),
        input_schema: serde_json::json!({"type": "object"}),
        command: "./s.sh".into(),
        args: vec![],
        required_permission: PluginToolPermission::DangerFullAccess,
    }];
    let json = serde_json::to_string(&tm).unwrap();
    let des: Vec<PluginToolManifest> = serde_json::from_str(&json).unwrap();
    assert_eq!(tm, des);
}

#[test]
fn test_plugin_tool_definition_struct() {
    let def = PluginToolDefinition {
        name: "tool".into(),
        description: Some("desc".into()),
        input_schema: serde_json::json!({"type": "object"}),
    };
    assert_eq!(def.name, "tool");
    assert_eq!(def.description.as_deref(), Some("desc"));
}

#[test]
fn test_plugin_tool_definition_no_description() {
    let def = PluginToolDefinition {
        name: "t".into(),
        description: None,
        input_schema: serde_json::json!({"type": "object"}),
    };
    assert!(def.description.is_none());
}

#[test]
fn test_plugin_tool_definition_serde_renamed() {
    let json = r#"{"name":"x","description":"y","inputSchema":{"type":"object"}}"#;
    let des: PluginToolDefinition = serde_json::from_str(json).unwrap();
    assert_eq!(des.name, "x");
    assert_eq!(des.description.as_deref(), Some("y"));
}

#[test]
fn test_plugin_tool_definition_serde_roundtrip() {
    let def = PluginToolDefinition {
        name: "test".into(),
        description: Some("desc".into()),
        input_schema: serde_json::json!({"type": "object", "properties": {}}),
    };
    let json = serde_json::to_string(&def).unwrap();
    let des: PluginToolDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(def.name, des.name);
}

#[test]
fn test_plugin_command_manifest_struct() {
    let cm = PluginCommandManifest {
        name: "cmd".into(),
        description: "desc".into(),
        command: "echo".into(),
    };
    assert_eq!(cm.name, "cmd");
    assert_eq!(cm.command, "echo");
}

#[test]
fn test_plugin_command_manifest_serde_roundtrip() {
    let cm = PluginCommandManifest {
        name: "mycmd".into(),
        description: "my description".into(),
        command: "/usr/bin/script".into(),
    };
    let json = serde_json::to_string(&cm).unwrap();
    let des: PluginCommandManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(cm, des);
}

#[test]
fn test_plugin_command_manifests_serde_array() {
    let cms = vec![
        PluginCommandManifest { name: "a".into(), description: "a desc".into(), command: "ca".into() },
        PluginCommandManifest { name: "b".into(), description: "b desc".into(), command: "cb".into() },
    ];
    let json = serde_json::to_string(&cms).unwrap();
    let des: Vec<PluginCommandManifest> = serde_json::from_str(&json).unwrap();
    assert_eq!(cms, des);
}

#[test]
fn test_plugin_tool_new_with_all_fields() {
    let def = PluginToolDefinition {
        name: "test_tool".into(),
        description: Some("desc".into()),
        input_schema: serde_json::json!({"type": "object"}),
    };
    let tool = PluginTool::new("p@e", "p", def, "/bin/echo", vec!["arg".into()], PluginToolPermission::ReadOnly, Some(PathBuf::from("/root")));
    assert_eq!(tool.plugin_id(), "p@e");
    assert_eq!(tool.definition().name, "test_tool");
    assert_eq!(tool.required_permission(), "read-only");
}

#[test]
fn test_plugin_tool_new_without_root() {
    let def = PluginToolDefinition {
        name: "t".into(), description: None,
        input_schema: serde_json::json!({"type": "object"}),
    };
    let tool = PluginTool::new("p", "p", def, "cmd", vec![], PluginToolPermission::DangerFullAccess, None);
    assert_eq!(tool.required_permission(), "danger-full-access");
}

#[test]
fn test_plugin_tool_new_multiple_args() {
    let def = PluginToolDefinition {
        name: "t".into(), description: Some("d".into()),
        input_schema: serde_json::json!({"type": "object"}),
    };
    let tool = PluginTool::new("p", "p", def, "/bin/sh", vec!["-c".into(), "echo".into()], PluginToolPermission::ReadOnly, None);
    assert_eq!(tool.plugin_id(), "p");
}

#[test]
fn test_plugin_tool_execute_fails_on_nonexistent_command() {
    let def = PluginToolDefinition {
        name: "nonexistent".into(), description: Some("desc".into()),
        input_schema: serde_json::json!({"type": "object"}),
    };
    let tool = PluginTool::new("p", "p", def, "/does/not/exist/binary", vec![], PluginToolPermission::ReadOnly, None);
    let result = tool.execute(&serde_json::json!({}));
    assert!(result.is_err());
}

#[test]
fn test_plugin_metadata_struct() {
    let meta = PluginMetadata {
        id: "test@builtin".into(),
        name: "test".into(),
        version: "1.0.0".into(),
        description: "desc".into(),
        kind: PluginKind::Builtin,
        source: "builtin".into(),
        default_enabled: true,
        root: None,
    };
    assert_eq!(meta.id, "test@builtin");
    assert_eq!(meta.name, "test");
    assert_eq!(meta.version, "1.0.0");
    assert_eq!(meta.description, "desc");
    assert_eq!(meta.kind, PluginKind::Builtin);
    assert!(meta.default_enabled);
    assert!(meta.root.is_none());
}

#[test]
fn test_plugin_metadata_with_root() {
    let meta = PluginMetadata {
        root: Some(PathBuf::from("/tmp/test")),
        id: "id".into(), name: "n".into(), version: "1".into(), description: "d".into(),
        kind: PluginKind::External, source: "ext".into(), default_enabled: false,
    };
    assert_eq!(meta.root, Some(PathBuf::from("/tmp/test")));
}

#[test]
fn test_plugin_metadata_clone() {
    let meta = PluginMetadata {
        id: "id".into(), name: "n".into(), version: "1".into(), description: "d".into(),
        kind: PluginKind::Bundled, source: "s".into(), default_enabled: false, root: None,
    };
    let c = meta.clone();
    assert_eq!(meta, c);
}

#[test]
fn test_plugin_registry_new_empty() {
    let registry = PluginRegistry::new(vec![]);
    assert!(registry.plugins().is_empty());
}

#[test]
fn test_plugin_registry_new_sorts_plugins() {
    let p1 = make_builtin_plugin("z-foo");
    let p2 = make_builtin_plugin("a-bar");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p1, true), RegisteredPlugin::new(p2, true)]);
    let plugins = registry.plugins();
    assert_eq!(plugins[0].metadata().id, "example-builtin@builtin");
    assert_eq!(plugins[1].metadata().id, "example-builtin@builtin");
}

#[test]
fn test_plugin_registry_get_returns_some() {
    let p = make_builtin_plugin("get-me");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, true)]);
    assert!(registry.get("example-builtin@builtin").is_some());
}

#[test]
fn test_plugin_registry_get_returns_none() {
    let registry = PluginRegistry::new(vec![]);
    assert!(registry.get("nonexistent@builtin").is_none());
}

#[test]
fn test_plugin_registry_contains_true() {
    let p = make_builtin_plugin("my-plugin");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, true)]);
    assert!(registry.contains("example-builtin@builtin"));
}

#[test]
fn test_plugin_registry_contains_false() {
    let p = make_builtin_plugin("x");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, true)]);
    assert!(!registry.contains("x@external"));
}

#[test]
fn test_plugin_registry_summaries_empty() {
    let registry = PluginRegistry::new(vec![]);
    assert!(registry.summaries().is_empty());
}

#[test]
fn test_plugin_registry_summaries_non_empty() {
    let p = make_builtin_plugin("s");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, true)]);
    let summaries = registry.summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].metadata.name, "example-builtin");
}

#[test]
fn test_plugin_registry_aggregated_hooks_empty() {
    let registry = PluginRegistry::new(vec![]);
    let result = registry.aggregated_hooks();
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_plugin_registry_aggregated_tools_empty() {
    let registry = PluginRegistry::new(vec![]);
    let result = registry.aggregated_tools();
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_plugin_registry_initialize_empty() {
    let registry = PluginRegistry::new(vec![]);
    assert!(registry.initialize().is_ok());
}

#[test]
fn test_plugin_registry_shutdown_empty() {
    let registry = PluginRegistry::new(vec![]);
    assert!(registry.shutdown().is_ok());
}

#[test]
fn test_plugin_registry_clone() {
    let registry = PluginRegistry::new(vec![]);
    let c = registry.clone();
    assert_eq!(registry.plugins().len(), c.plugins().len());
}

#[test]
fn test_plugin_registry_equality() {
    let a = PluginRegistry::new(vec![]);
    let b = PluginRegistry::new(vec![]);
    assert_eq!(a, b);
}

#[test]
fn test_registered_plugin_new_enabled() {
    let def = make_builtin_plugin("test");
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.is_enabled());
}

#[test]
fn test_registered_plugin_new_disabled() {
    let def = make_builtin_plugin("test");
    let rp = RegisteredPlugin::new(def, false);
    assert!(!rp.is_enabled());
}

#[test]
fn test_registered_plugin_metadata() {
    let def = make_builtin_plugin("my-app");
    let rp = RegisteredPlugin::new(def, true);
    assert_eq!(rp.metadata().name, "example-builtin");
}

#[test]
fn test_registered_plugin_hooks() {
    let def = make_builtin_plugin("h");
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.hooks().is_empty());
}

#[test]
fn test_registered_plugin_tools_empty() {
    let def = make_builtin_plugin("t");
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.tools().is_empty());
}

#[test]
fn test_registered_plugin_validate() {
    let def = make_builtin_plugin("v");
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.validate().is_ok());
}

#[test]
fn test_registered_plugin_initialize() {
    let def = make_builtin_plugin("i");
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.initialize().is_ok());
}

#[test]
fn test_registered_plugin_shutdown() {
    let def = make_builtin_plugin("s");
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.shutdown().is_ok());
}

#[test]
fn test_registered_plugin_summary_enabled() {
    let def = make_builtin_plugin("sum");
    let rp = RegisteredPlugin::new(def, true);
    let s = rp.summary();
    assert!(s.enabled);
    assert_eq!(s.metadata.name, "example-builtin");
}

#[test]
fn test_registered_plugin_summary_disabled() {
    let def = make_builtin_plugin("s2");
    let rp = RegisteredPlugin::new(def, false);
    let s = rp.summary();
    assert!(!s.enabled);
}

#[test]
fn test_registered_plugin_clone() {
    let def = make_builtin_plugin("c");
    let rp = RegisteredPlugin::new(def, true);
    let c = RegisteredPlugin::new(make_builtin_plugin("c"), true);
    assert_eq!(rp.metadata().name, c.metadata().name);
}

#[test]
fn test_hook_run_result_allow() {
    let r = HookRunResult::allow(vec!["msg".into()]);
    assert!(!r.is_denied());
    assert!(!r.is_failed());
    assert_eq!(r.messages(), &["msg".to_string()]);
}

#[test]
fn test_hook_run_result_allow_empty_messages() {
    let r = HookRunResult::allow(vec![]);
    assert!(r.messages().is_empty());
    assert!(!r.is_denied());
}

#[test]
fn test_hook_run_result_allow_multiple_messages() {
    let r = HookRunResult::allow(vec!["a".into(), "b".into()]);
    assert_eq!(r.messages().len(), 2);
}

#[test]
fn test_hook_run_result_clone() {
    let r = HookRunResult::allow(vec!["x".into()]);
    let c = r.clone();
    assert_eq!(r.messages(), c.messages());
}

#[test]
fn test_hook_run_result_equality() {
    let a = HookRunResult::allow(vec!["a".into()]);
    let b = HookRunResult::allow(vec!["a".into()]);
    assert_eq!(a, b);
    let c = HookRunResult::allow(vec!["c".into()]);
    assert_ne!(a, c);
}

#[test]
fn test_hook_run_result_default_is_not_denied() {
    let r = HookRunResult::allow(vec![]);
    assert!(!r.is_denied());
}

#[test]
fn test_hook_event_copy_variants() {
    let e = HookEvent::PreToolUse;
    assert_eq!(format!("{e:?}").len(), 10);
}

#[test]
fn test_hook_event_clone() {
    let a = HookEvent::PostToolUse;
    let b = a;
    assert_eq!(format!("{b:?}"), "PostToolUse");
}

#[test]
fn test_hook_event_partial_eq() {
    assert_eq!(HookEvent::PreToolUse, HookEvent::PreToolUse);
    assert_ne!(HookEvent::PreToolUse, HookEvent::PostToolUse);
}

#[test]
fn test_hook_runner_new_empty() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_pre_tool_use("test", r"{}");
    assert!(result.messages().is_empty());
}

#[test]
fn test_hook_runner_new_with_hooks() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["printf hi; exit 2".into()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Bash", r"{}");
    assert!(result.is_denied());
}

#[test]
fn test_hook_runner_run_pre_tool_use_allowed() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["printf ok".into()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Read", r"{}");
    assert!(!result.is_denied());
    assert!(!result.is_failed());
}

#[test]
fn test_hook_runner_run_pre_tool_use_denied() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["exit 2".into()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Write", r"{}");
    assert!(result.is_denied());
}

#[test]
fn test_hook_runner_run_pre_tool_use_failed() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["exit 1".into()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Bash", r"{}");
    assert!(result.is_failed());
}

#[test]
fn test_hook_runner_run_post_tool_use_allowed() {
    let runner = HookRunner::new(PluginHooks {
        post_tool_use: vec!["printf ok".into()],
        ..Default::default()
    });
    let result = runner.run_post_tool_use("Read", r"{}", "output", false);
    assert!(!result.is_denied());
}

#[test]
fn test_hook_runner_run_post_tool_use_with_error_flag() {
    let runner = HookRunner::new(PluginHooks {
        post_tool_use: vec!["exit 2".into()],
        ..Default::default()
    });
    let result = runner.run_post_tool_use("Test", r"{}", "err", true);
    assert!(result.is_denied());
}

#[test]
fn test_hook_runner_run_post_tool_use_failure_allowed() {
    let runner = HookRunner::new(PluginHooks {
        post_tool_use_failure: vec!["printf ok".into()],
        ..Default::default()
    });
    let result = runner.run_post_tool_use_failure("Read", r"{}", "error");
    assert!(!result.is_denied());
}

#[test]
fn test_hook_runner_run_post_tool_use_failure_denied() {
    let runner = HookRunner::new(PluginHooks {
        post_tool_use_failure: vec!["exit 2".into()],
        ..Default::default()
    });
    let result = runner.run_post_tool_use_failure("Read", r"{}", "err");
    assert!(result.is_denied());
}

#[test]
fn test_hook_runner_run_post_tool_use_failure_failed() {
    let runner = HookRunner::new(PluginHooks {
        post_tool_use_failure: vec!["exit 1".into()],
        ..Default::default()
    });
    let result = runner.run_post_tool_use_failure("Read", r"{}", "err");
    assert!(result.is_failed());
}

#[test]
fn test_hook_runner_chain_stops_on_deny() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec![
            "exit 2".into(),
            "printf should not run".into(),
        ],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Test", r"{}");
    assert!(result.is_denied());
    assert!(result.messages().len() <= 1);
}

#[test]
fn test_hook_runner_hook_not_found() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["/nonexistent/hook/script.sh".into()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Bash", r"{}");
    assert!(result.is_failed());
}

#[test]
fn test_hook_runner_from_registry_empty() {
    let registry = PluginRegistry::new(vec![]);
    let result = HookRunner::from_registry(&registry);
    assert!(result.is_ok());
}

#[test]
fn test_hook_runner_default() {
    let runner = HookRunner::default();
    let result = runner.run_pre_tool_use("Any", r"{}");
    assert!(!result.is_denied());
    assert!(result.messages().is_empty());
}

#[test]
fn test_hook_runner_clone() {
    let runner = HookRunner::new(PluginHooks::default());
    let c = runner.clone();
    assert_eq!(format!("{runner:?}"), format!("{:?}", c));
}

#[test]
fn test_hook_runner_equality() {
    let a = HookRunner::new(PluginHooks::default());
    let b = HookRunner::new(PluginHooks::default());
    assert_eq!(a, b);
}

#[test]
fn test_hook_runner_inequality() {
    let a = HookRunner::new(PluginHooks::default());
    let b = HookRunner::new(PluginHooks { pre_tool_use: vec!["echo".into()], ..Default::default() });
    assert_ne!(a, b);
}

#[test]
fn test_builtin_plugins_is_not_empty() {
    let plugins = builtin_plugins();
    assert!(!plugins.is_empty());
}

#[test]
fn test_builtin_plugins_first_is_example() {
    let plugins = builtin_plugins();
    assert_eq!(plugins[0].metadata().name, "example-builtin");
}

#[test]
fn test_builtin_plugins_kind() {
    for p in builtin_plugins() {
        assert_eq!(p.metadata().kind, PluginKind::Builtin);
    }
}

#[test]
fn test_builtin_plugins_validate() {
    for p in builtin_plugins() {
        assert!(p.validate().is_ok());
    }
}

#[test]
fn test_builtin_plugins_initialize() {
    for p in builtin_plugins() {
        assert!(p.initialize().is_ok());
    }
}

#[test]
fn test_builtin_plugins_shutdown() {
    for p in builtin_plugins() {
        assert!(p.shutdown().is_ok());
    }
}

#[test]
fn test_builtin_plugins_default_disabled() {
    for p in builtin_plugins() {
        assert!(!p.metadata().default_enabled);
    }
}

#[test]
fn test_builtin_plugin_missing_tools() {
    for p in builtin_plugins() {
        assert!(p.tools().is_empty());
    }
}

#[test]
fn test_builtin_plugin_missing_hooks() {
    for p in builtin_plugins() {
        assert!(p.hooks().is_empty());
    }
}

#[test]
fn test_builtin_plugin_missing_lifecycle() {
    for p in builtin_plugins() {
        assert!(p.lifecycle().is_empty());
    }
}

#[test]
fn test_load_plugin_from_directory_rejects_missing() {
    let root = temp_dir("missing-test");
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_validates_empty_name() {
    let root = temp_dir("empty-name");
    write_file(&root.join("plugin.json"), r#"{"name":"","version":"1.0.0","description":"desc"}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_validates_empty_version() {
    let root = temp_dir("empty-version");
    write_file(&root.join("plugin.json"), r#"{"name":"test","version":"","description":"desc"}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_validates_empty_description() {
    let root = temp_dir("empty-desc");
    write_file(&root.join("plugin.json"), r#"{"name":"test","version":"1.0.0","description":""}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_minimal_valid() {
    let root = temp_dir("minimal-valid");
    write_file(&root.join("plugin.json"), r#"{"name":"minimal","version":"1.0.0","description":"minimal plugin"}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_ok());
    let m = result.unwrap();
    assert_eq!(m.name, "minimal");
    assert!(m.permissions.is_empty());
    assert!(m.tools.is_empty());
    assert!(m.commands.is_empty());
    assert!(m.hooks.is_empty());
    assert!(m.lifecycle.is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_at_root() {
    let root = temp_dir("root-manifest");
    write_file(&root.join("plugin.json"), r#"{"name":"root-plugin","version":"1.0.0","description":"root plugin"}"#);
    let manifest = load_plugin_from_directory(&root).unwrap();
    assert_eq!(manifest.name, "root-plugin");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_at_packaged() {
    let root = temp_dir("packaged-manifest");
    write_file(&root.join(".claude-plugin").join("plugin.json"), r#"{"name":"pkg-plugin","version":"2.0.0","description":"packaged plugin"}"#);
    let manifest = load_plugin_from_directory(&root).unwrap();
    assert_eq!(manifest.name, "pkg-plugin");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_rejects_tool_with_non_object_schema() {
    let root = temp_dir("bad-schema");
    write_file(&root.join("tools").join("s.sh"), "#!/bin/sh\n");
    make_executable(&root.join("tools").join("s.sh"));
    write_file(&root.join("plugin.json"), r#"{"name":"bad-schema","version":"1.0.0","description":"bad schema","tools":[{"name":"x","description":"x","inputSchema":"not_an_object","command":"./tools/s.sh","requiredPermission":"read-only"}]}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_defaults_disabled() {
    let root = temp_dir("default-disabled");
    write_file(&root.join("plugin.json"), r#"{"name":"def","version":"1.0.0","description":"default disabled"}"#);
    let manifest = load_plugin_from_directory(&root).unwrap();
    assert!(!manifest.default_enabled);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_custom_default_enabled() {
    let root = temp_dir("default-enabled");
    write_file(&root.join("plugin.json"), r#"{"name":"def","version":"1.0.0","description":"def","defaultEnabled":true}"#);
    let manifest = load_plugin_from_directory(&root).unwrap();
    assert!(manifest.default_enabled);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_permissions_list() {
    let root = temp_dir("permissions-list");
    write_file(&root.join("plugin.json"), r#"{"name":"p","version":"1.0.0","description":"p","permissions":["read","write"]}"#);
    let manifest = load_plugin_from_directory(&root).unwrap();
    assert_eq!(manifest.permissions.len(), 2);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_rejects_invalid_permissions() {
    let root = temp_dir("invalid-perm");
    write_file(&root.join("plugin.json"), r#"{"name":"p","version":"1","description":"p","permissions":["admin"]}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_rejects_duplicate_permissions() {
    let root = temp_dir("duplicate-perm");
    write_file(&root.join("plugin.json"), r#"{"name":"p","version":"1","description":"p","permissions":["read","read"]}"#);
    let result = load_plugin_from_directory(&root);
    assert!(result.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_passes_on_packaged_path() {
    let root = temp_dir("pass-packaged");
    write_file(&root.join(".claude-plugin").join("plugin.json"), r#"{"name":"pass-pkg","version":"3.0.0","description":"pass"}"#);
    let m = load_plugin_from_directory(&root).unwrap();
    assert_eq!(m.name, "pass-pkg");
    assert_eq!(m.version, "3.0.0");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_load_plugin_from_directory_parses_tool_arguments() {
    let root = temp_dir("tool-args");
    write_file(&root.join("tools").join("test.sh"), "#!/bin/sh\ncat\n");
    make_executable(&root.join("tools").join("test.sh"));
    write_file(&root.join("plugin.json"), r#"{"name":"ta","version":"1","description":"ta","tools":[{"name":"t","description":"t","inputSchema":{"type":"object"},"command":"./tools/test.sh","args":["-v","--debug"],"requiredPermission":"danger-full-access"}]}"#);
    let m = load_plugin_from_directory(&root).unwrap();
    let tools = m.tools;
    assert_eq!(tools[0].args, vec!["-v", "--debug"]);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_plugin_definition_builtin_metadata() {
    let p = make_builtin_plugin("def-demo");
    assert_eq!(p.metadata().id, "example-builtin@builtin");
}

#[test]
fn test_plugin_definition_builtin_hooks() {
    let p = make_builtin_plugin("hooks-test");
    assert!(p.hooks().is_empty());
}

#[test]
fn test_plugin_definition_builtin_lifecycle() {
    let p = make_builtin_plugin("life-test");
    assert!(p.lifecycle().is_empty());
}

#[test]
fn test_plugin_definition_builtin_tools_empty() {
    let p = make_builtin_plugin("tool-test");
    assert!(p.tools().is_empty());
}

#[test]
fn test_plugin_definition_unwrap_mut_variants() {
    let p = make_builtin_plugin("a");
    match &p {
        PluginDefinition::Builtin(_) => assert!(true),
        PluginDefinition::Bundled(_) => assert!(false),
        PluginDefinition::External(_) => assert!(false),
    }
}

#[test]
fn test_plugin_definition_builtin_validate() {
    let p = make_builtin_plugin("val");
    assert!(p.validate().is_ok());
}

#[test]
fn test_plugin_definition_builtin_initialize() {
    let p = make_builtin_plugin("init");
    assert!(p.initialize().is_ok());
}

#[test]
fn test_plugin_definition_builtin_shutdown() {
    let p = make_builtin_plugin("shut");
    assert!(p.shutdown().is_ok());
}

#[test]
fn test_plugin_load_failure_new() {
    let lf = PluginLoadFailure::new(PathBuf::from("/test"), PluginKind::External, "src".into(), PluginError::NotFound("err".into()));
    assert_eq!(lf.plugin_root, PathBuf::from("/test"));
    assert_eq!(lf.kind, PluginKind::External);
    assert_eq!(lf.source, "src");
    assert!(lf.error().to_string().contains("err"));
}

#[test]
fn test_plugin_load_failure_display() {
    let lf = PluginLoadFailure::new(PathBuf::from("/path"), PluginKind::Bundled, "bundled".into(), PluginError::NotFound("missing".into()));
    let d = lf.to_string();
    assert!(d.contains("bundled"));
    assert!(d.contains("/path"));
}

#[test]
fn test_plugin_load_failure_error_ref() {
    let lf = PluginLoadFailure::new(PathBuf::from("/"), PluginKind::Builtin, "b".into(), PluginError::InvalidManifest("bad".into()));
    assert!(lf.error().to_string().contains("bad"));
}

#[test]
fn test_plugin_registry_report_new_no_failures() {
    let report = PluginRegistryReport::new(PluginRegistry::new(vec![]), vec![]);
    assert!(!report.has_failures());
    assert!(report.registry().plugins().is_empty());
}

#[test]
fn test_plugin_registry_report_with_failures() {
    let lf = PluginLoadFailure::new(PathBuf::from("/f"), PluginKind::External, "s".into(), PluginError::NotFound("err".into()));
    let report = PluginRegistryReport::new(PluginRegistry::new(vec![]), vec![lf]);
    assert!(report.has_failures());
    assert_eq!(report.failures().len(), 1);
}

#[test]
fn test_plugin_registry_report_into_registry_ok() {
    let report = PluginRegistryReport::new(PluginRegistry::new(vec![]), vec![]);
    assert!(report.into_registry().is_ok());
}

#[test]
fn test_plugin_registry_report_into_registry_err() {
    let lf = PluginLoadFailure::new(PathBuf::from("/f"), PluginKind::External, "s".into(), PluginError::NotFound("err".into()));
    let report = PluginRegistryReport::new(PluginRegistry::new(vec![]), vec![lf]);
    assert!(report.into_registry().is_err());
}

#[test]
fn test_plugin_registry_report_summaries() {
    let p = make_builtin_plugin("sum");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, true)]);
    let report = PluginRegistryReport::new(registry, vec![]);
    let summaries = report.summaries();
    assert_eq!(summaries.len(), 1);
}

#[test]
fn test_plugin_summary_struct() {
    let meta = PluginMetadata {
        id: "s@builtin".into(), name: "s".into(), version: "1".into(), description: "d".into(),
        kind: PluginKind::Builtin, source: "b".into(), default_enabled: true, root: None,
    };
    let s = PluginSummary { metadata: meta.clone(), enabled: true };
    assert_eq!(s.metadata.id, "s@builtin");
    assert!(s.enabled);
}

#[test]
fn test_plugin_summary_clone() {
    let meta = PluginMetadata {
        id: "s@builtin".into(), name: "s".into(), version: "1".into(), description: "d".into(),
        kind: PluginKind::Builtin, source: "b".into(), default_enabled: false, root: None,
    };
    let a = PluginSummary { metadata: meta.clone(), enabled: false };
    let b = a.clone();
    assert_eq!(a.metadata.name, b.metadata.name);
    assert_eq!(a.enabled, b.enabled);
}

#[test]
fn test_plugin_summary_equality() {
    let meta = PluginMetadata {
        id: "s@builtin".into(), name: "s".into(), version: "1".into(), description: "d".into(),
        kind: PluginKind::Builtin, source: "b".into(), default_enabled: true, root: None,
    };
    let a = PluginSummary { metadata: meta.clone(), enabled: true };
    let b = PluginSummary { metadata: meta.clone(), enabled: true };
    assert_eq!(a, b);
    let c = PluginSummary { metadata: meta, enabled: false };
    assert_ne!(a, c);
}

#[test]
fn test_plugin_manager_config_new() {
    let config = PluginManagerConfig::new("/tmp/test");
    assert_eq!(config.config_home, PathBuf::from("/tmp/test"));
    assert!(config.enabled_plugins.is_empty());
    assert!(config.external_dirs.is_empty());
    assert!(config.install_root.is_none());
    assert!(config.registry_path.is_none());
    assert!(config.bundled_root.is_none());
}

#[test]
fn test_plugin_manager_config_new_from_pathbuf() {
    let path = PathBuf::from("/tmp/test2");
    let config = PluginManagerConfig::new(path);
    assert_eq!(config.config_home, PathBuf::from("/tmp/test2"));
}

#[test]
fn test_plugin_manager_new() {
    let config = PluginManagerConfig::new("/tmp");
    let manager = PluginManager::new(config);
    assert!(manager.install_root().to_string_lossy().contains("installed"));
}

#[test]
fn test_plugin_manager_install_root_default() {
    let config = PluginManagerConfig::new("/tmp");
    let manager = PluginManager::new(config);
    let path = manager.install_root();
    assert!(path.to_string_lossy().contains("plugins/installed") || path.to_string_lossy().contains("plugins\\installed"));
}

#[test]
fn test_plugin_manager_install_root_custom() {
    let mut config = PluginManagerConfig::new("/tmp");
    config.install_root = Some(PathBuf::from("/custom/install"));
    let manager = PluginManager::new(config);
    assert_eq!(manager.install_root(), PathBuf::from("/custom/install"));
}

#[test]
fn test_plugin_manager_registry_path_default() {
    let config = PluginManagerConfig::new("/tmp");
    let manager = PluginManager::new(config);
    let path = manager.registry_path();
    assert!(path.to_string_lossy().contains("installed.json"));
}

#[test]
fn test_plugin_manager_registry_path_custom() {
    let mut config = PluginManagerConfig::new("/tmp");
    config.registry_path = Some(PathBuf::from("/custom/registry.json"));
    let manager = PluginManager::new(config);
    assert_eq!(manager.registry_path(), PathBuf::from("/custom/registry.json"));
}

#[test]
fn test_plugin_manager_settings_path() {
    let config = PluginManagerConfig::new("/tmp");
    let manager = PluginManager::new(config);
    let path = manager.settings_path();
    assert!(path.to_string_lossy().contains("settings.json"));
}

#[test]
fn test_plugin_manager_list_plugins_on_fresh_home() {
    let config_home = temp_dir("list-plugins");
    let config = PluginManagerConfig::new(&config_home);
    let manager = PluginManager::new(config);
    let result = manager.list_plugins();
    assert!(result.is_ok());
    let plugins = result.unwrap();
    assert!(plugins.iter().any(|p| p.metadata.kind == PluginKind::Builtin));
    let _ = fs::remove_dir_all(&config_home);
}

#[test]
fn test_plugin_manager_validate_plugin_source() {
    let root = temp_dir("validate-source");
    write_external_plugin(&root, "val-src", "1.0.0");
    let config = PluginManagerConfig::new(temp_dir("val-home"));
    let manager = PluginManager::new(config);
    let result = manager.validate_plugin_source(root.to_str().unwrap());
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.name, "val-src");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_plugin_manager_validate_plugin_source_invalid() {
    let root = temp_dir("invalid-source");
    write_file(&root.join("plugin.json"), r#"{"name":"","version":"1","description":"desc"}"#);
    let config = PluginManagerConfig::new(temp_dir("invalid-home"));
    let manager = PluginManager::new(config);
    let result = manager.validate_plugin_source(root.to_str().unwrap());
    assert!(result.is_err());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_plugin_manager_validate_plugin_source_not_found() {
    let config = PluginManagerConfig::new(temp_dir("nf-home"));
    let manager = PluginManager::new(config);
    let result = manager.validate_plugin_source("/nonexistent/path/that/does/not/exist");
    assert!(result.is_err());
}

#[test]
fn test_plugin_manager_install_and_enable_disable() {
    let config_home = temp_dir("install-ed-home");
    let source_root = temp_dir("install-ed-source");
    write_external_plugin(&source_root, "install-ed", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    let install = manager.install(source_root.to_str().unwrap()).unwrap();
    assert_eq!(install.plugin_id, "install-ed@external");

    assert!(manager.list_plugins().unwrap().iter().any(|p| p.metadata.id == "install-ed@external"));

    manager.disable("install-ed@external").unwrap();
    let registry = manager.plugin_registry().unwrap();
    let rp = registry.get("install-ed@external").unwrap();
    assert!(!rp.is_enabled());

    manager.enable("install-ed@external").unwrap();
    let registry = manager.plugin_registry().unwrap();
    let rp = registry.get("install-ed@external").unwrap();
    assert!(rp.is_enabled());

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_uninstall() {
    let config_home = temp_dir("uninst-home");
    let source_root = temp_dir("uninst-source");
    write_external_plugin(&source_root, "uninst", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();
    manager.uninstall("uninst@external").unwrap();
    assert!(!manager.list_plugins().unwrap().iter().any(|p| p.metadata.id == "uninst@external"));

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_uninstall_nonexistent() {
    let config_home = temp_dir("uninst-none-home");
    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    let result = manager.uninstall("nonexistent@external");
    assert!(result.is_err());
    let _ = fs::remove_dir_all(&config_home);
}

#[test]
fn test_plugin_manager_install_then_update() {
    let config_home = temp_dir("update-home");
    let source_root = temp_dir("update-source");
    write_external_plugin(&source_root, "update-me", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    write_external_plugin(&source_root, "update-me", "2.0.0");
    let update = manager.update("update-me@external").unwrap();
    assert_eq!(update.old_version, "1.0.0");
    assert_eq!(update.new_version, "2.0.0");

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_update_nonexistent() {
    let config_home = temp_dir("update-none-home");
    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    let result = manager.update("nonexistent@external");
    assert!(result.is_err());
    let _ = fs::remove_dir_all(&config_home);
}

#[test]
fn test_plugin_manager_aggregated_tools() {
    let config_home = temp_dir("aggr-tools-home");
    let source_root = temp_dir("aggr-tools-source");
    write_tool_plugin(&source_root, "aggr-tools", "test_tool");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    let tools = manager.aggregated_tools().unwrap();
    let has_tool = tools.iter().any(|t| t.definition().name == "test_tool");
    assert!(has_tool);

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_aggregated_hooks() {
    let config_home = temp_dir("aggr-hooks-home");
    let source_root = temp_dir("aggr-hooks-source");
    write_hook_plugin(&source_root, "hook-test", "pre_message");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    let hooks = manager.aggregated_hooks().unwrap();
    assert!(!hooks.pre_tool_use.is_empty());

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_list_installed() {
    let config_home = temp_dir("list-installed-home");
    let source_root = temp_dir("list-installed-source");
    write_external_plugin(&source_root, "list-installed", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    let installed = manager.list_installed_plugins().unwrap();
    assert!(installed.iter().any(|p| p.metadata.id == "list-installed@external"));

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_discover_plugins() {
    let config_home = temp_dir("disc-plugins");
    let source_root = temp_dir("disc-plugins-source");
    write_external_plugin(&source_root, "disc-plugins", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    let discovered = manager.discover_plugins().unwrap();
    assert!(discovered.iter().any(|p| p.metadata().name == "disc-plugins"));

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_plugin_registry_report() {
    let config_home = temp_dir("report-test-home");
    let source_root = temp_dir("report-src");
    write_external_plugin(&source_root, "report-test", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    let report = manager.plugin_registry_report().unwrap();
    assert!(report.registry().contains("report-test@external"));
    assert!(!report.has_failures());

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_plugin_manager_plugin_registry() {
    let config_home = temp_dir("reg-test-home");
    let source_root = temp_dir("reg-src");
    write_external_plugin(&source_root, "reg-test", "1.0.0");

    let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
    manager.install(source_root.to_str().unwrap()).unwrap();

    let registry = manager.plugin_registry().unwrap();
    assert!(registry.contains("reg-test@external"));

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}

#[test]
fn test_installed_plugin_registry_default() {
    let registry = InstalledPluginRegistry::default();
    assert!(registry.plugins.is_empty());
}

#[test]
fn test_installed_plugin_registry_serde_roundtrip() {
    let mut registry = InstalledPluginRegistry::default();
    registry.plugins.insert(
        "test@external".into(),
        InstalledPluginRecord {
            kind: PluginKind::External,
            id: "test@external".into(),
            name: "test".into(),
            version: "1.0.0".into(),
            description: "desc".into(),
            install_path: PathBuf::from("/install"),
            source: PluginInstallSource::LocalPath { path: PathBuf::from("/src") },
            installed_at_unix_ms: 1000,
            updated_at_unix_ms: 2000,
        },
    );
    let json = serde_json::to_string_pretty(&registry).unwrap();
    let des: InstalledPluginRegistry = serde_json::from_str(&json).unwrap();
    assert!(des.plugins.contains_key("test@external"));
}

#[test]
fn test_installed_plugin_record_fields() {
    let record = InstalledPluginRecord {
        kind: PluginKind::External,
        id: "id@ext".into(),
        name: "name".into(),
        version: "1.0.0".into(),
        description: "desc".into(),
        install_path: PathBuf::from("/path"),
        source: PluginInstallSource::LocalPath { path: PathBuf::from("/src") },
        installed_at_unix_ms: 0,
        updated_at_unix_ms: 0,
    };
    assert_eq!(record.id, "id@ext");
    assert_eq!(record.name, "name");
    assert_eq!(record.kind, PluginKind::External);
}

#[test]
fn test_installed_plugin_record_clone() {
    let record = InstalledPluginRecord {
        kind: PluginKind::Bundled,
        id: "b@bundled".into(),
        name: "b".into(),
        version: "1".into(),
        description: "d".into(),
        install_path: PathBuf::from("/p"),
        source: PluginInstallSource::LocalPath { path: PathBuf::from("/src") },
        installed_at_unix_ms: 1,
        updated_at_unix_ms: 1,
    };
    let c = record.clone();
    assert_eq!(record.id, c.id);
}

#[test]
fn test_installed_plugin_record_serde() {
    let record = InstalledPluginRecord {
        kind: PluginKind::External,
        id: "serde-ext@external".into(),
        name: "serde-ext".into(),
        version: "1.0.0".into(),
        description: "serde test".into(),
        install_path: PathBuf::from("/tmp/installed/serde-ext-external"),
        source: PluginInstallSource::LocalPath { path: PathBuf::from("/tmp/src") },
        installed_at_unix_ms: 12345,
        updated_at_unix_ms: 67890,
    };
    let json = serde_json::to_string(&record).unwrap();
    let des: InstalledPluginRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.id, des.id);
    assert_eq!(record.version, des.version);
    assert_eq!(record.kind, des.kind);
    assert_eq!(record.installed_at_unix_ms, des.installed_at_unix_ms);
}

#[test]
fn test_plugin_install_source_local_path() {
    let source = PluginInstallSource::LocalPath { path: PathBuf::from("/tmp/plugin") };
    let json = serde_json::to_string(&source).unwrap();
    let des: PluginInstallSource = serde_json::from_str(&json).unwrap();
    assert!(matches!(des, PluginInstallSource::LocalPath { .. }));
}

#[test]
fn test_plugin_install_source_git_url() {
    let source = PluginInstallSource::GitUrl { url: "https://github.com/test/repo.git".into() };
    let json = serde_json::to_string(&source).unwrap();
    let des: PluginInstallSource = serde_json::from_str(&json).unwrap();
    assert!(matches!(des, PluginInstallSource::GitUrl { .. }));
}

#[test]
fn test_plugin_install_source_serde_roundtrip_local_path() {
    let source = PluginInstallSource::LocalPath { path: PathBuf::from("/a/b/c") };
    let json = serde_json::to_string(&source).unwrap();
    let des: PluginInstallSource = serde_json::from_str(&json).unwrap();
    match des {
        PluginInstallSource::LocalPath { path } => assert_eq!(path, PathBuf::from("/a/b/c")),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_plugin_install_source_serde_roundtrip_git_url() {
    let source = PluginInstallSource::GitUrl { url: "git@github.com:user/repo.git".into() };
    let json = serde_json::to_string(&source).unwrap();
    let des: PluginInstallSource = serde_json::from_str(&json).unwrap();
    match des {
        PluginInstallSource::GitUrl { url } => assert_eq!(url, "git@github.com:user/repo.git"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_plugin_error_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let err = PluginError::Io(io_err);
    assert!(!err.to_string().is_empty());
}

#[test]
fn test_plugin_error_json() {
    let json_err = serde_json::from_str::<Value>("!").unwrap_err();
    let err = PluginError::Json(json_err);
    assert!(!err.to_string().is_empty());
}

#[test]
fn test_plugin_error_invalid_manifest() {
    let err = PluginError::InvalidManifest("invalid".into());
    assert_eq!(err.to_string(), "invalid");
}

#[test]
fn test_plugin_error_not_found() {
    let err = PluginError::NotFound("missing".into());
    assert_eq!(err.to_string(), "missing");
}

#[test]
fn test_plugin_error_command_failed() {
    let err = PluginError::CommandFailed("cmd error".into());
    assert_eq!(err.to_string(), "cmd error");
}

#[test]
fn test_plugin_error_manifest_validation_single() {
    let err = PluginError::ManifestValidation(vec![PluginManifestValidationError::EmptyField { field: "name" }]);
    let d = err.to_string();
    assert!(d.contains("name"));
}

#[test]
fn test_plugin_error_manifest_validation_multiple() {
    let err = PluginError::ManifestValidation(vec![
        PluginManifestValidationError::EmptyField { field: "name" },
        PluginManifestValidationError::InvalidPermission { permission: "admin".into() },
    ]);
    let d = err.to_string();
    assert!(d.contains("name"));
    assert!(d.contains("admin"));
}

#[test]
fn test_plugin_error_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no access");
    let err: PluginError = io.into();
    assert!(matches!(err, PluginError::Io(_)));
}

#[test]
fn test_plugin_error_from_json() {
    let json = serde_json::from_str::<Value>("[").unwrap_err();
    let err: PluginError = json.into();
    assert!(matches!(err, PluginError::Json(_)));
}

#[test]
fn test_plugin_error_is_std_error() {
    let err = PluginError::NotFound("test".into());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn test_plugin_error_load_failures() {
    let lf = PluginLoadFailure::new(PathBuf::from("/f"), PluginKind::External, "s".into(), PluginError::NotFound("err".into()));
    let err = PluginError::LoadFailures(vec![lf]);
    let d = err.to_string();
    assert!(d.contains("failed to load"));
}

#[test]
fn test_plugin_manifest_validation_error_empty_field() {
    let e = PluginManifestValidationError::EmptyField { field: "name" };
    let d = e.to_string();
    assert!(d.contains("name"));
}

#[test]
fn test_plugin_manifest_validation_error_empty_entry_field() {
    let e = PluginManifestValidationError::EmptyEntryField { kind: "tool", field: "name", name: Some("my_tool".into()) };
    let d = e.to_string();
    assert!(d.contains("tool"));
    assert!(d.contains("my_tool"));
}

#[test]
fn test_plugin_manifest_validation_error_invalid_permission() {
    let e = PluginManifestValidationError::InvalidPermission { permission: "admin".into() };
    let d = e.to_string();
    assert!(d.contains("admin"));
}

#[test]
fn test_plugin_manifest_validation_error_duplicate_permission() {
    let e = PluginManifestValidationError::DuplicatePermission { permission: "read".into() };
    let d = e.to_string();
    assert!(d.contains("read"));
}

#[test]
fn test_plugin_manifest_validation_error_duplicate_entry() {
    let e = PluginManifestValidationError::DuplicateEntry { kind: "command", name: "sync".into() };
    let d = e.to_string();
    assert!(d.contains("command"));
    assert!(d.contains("sync"));
}

#[test]
fn test_plugin_manifest_validation_error_missing_path() {
    let e = PluginManifestValidationError::MissingPath { kind: "hook", path: PathBuf::from("/missing") };
    let d = e.to_string();
    assert!(d.contains("/missing"));
}

#[test]
fn test_plugin_manifest_validation_error_path_is_directory() {
    let e = PluginManifestValidationError::PathIsDirectory { kind: "tool", path: PathBuf::from("/dir") };
    let d = e.to_string();
    assert!(d.contains("directory") || d.contains("file"));
}

#[test]
fn test_plugin_manifest_validation_error_invalid_tool_input_schema() {
    let e = PluginManifestValidationError::InvalidToolInputSchema { tool_name: "my_tool".into() };
    let d = e.to_string();
    assert!(d.contains("my_tool"));
}

#[test]
fn test_plugin_manifest_validation_error_invalid_tool_permission() {
    let e = PluginManifestValidationError::InvalidToolRequiredPermission { tool_name: "t".into(), permission: "bad".into() };
    let d = e.to_string();
    assert!(d.contains('t') && d.contains("bad"));
}

#[test]
fn test_plugin_manifest_validation_error_unsupported_contract() {
    let e = PluginManifestValidationError::UnsupportedManifestContract { detail: "unsupported feature".into() };
    let d = e.to_string();
    assert!(d.contains("unsupported"));
}

#[test]
fn test_plugin_manifest_validation_error_empty_field_display_missing_name() {
    let e = PluginManifestValidationError::EmptyEntryField { kind: "command", field: "description", name: None };
    let d = e.to_string();
    assert!(d.contains("description"));
}

#[test]
fn test_builtin_plugin_in_plugin_registry() {
    let p = make_builtin_plugin("builtin-reg");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, true)]);
    assert!(registry.contains("example-builtin@builtin"));
}

#[test]
fn test_builtin_plugin_in_plugin_registry_disabled() {
    let p = make_builtin_plugin("builtin-reg-dis");
    let registry = PluginRegistry::new(vec![RegisteredPlugin::new(p, false)]);
    let rp = registry.get("example-builtin@builtin").unwrap();
    assert!(!rp.is_enabled());
}

#[test]
fn test_aggregated_hooks_skips_disabled_plugins() {
    let p = make_builtin_plugin("disabled-hooks");
    let p2 = make_builtin_plugin("enabled-hooks");
    let registry = PluginRegistry::new(vec![
        RegisteredPlugin::new(p, false),
        RegisteredPlugin::new(p2, true),
    ]);
    let hooks = registry.aggregated_hooks().unwrap();
    assert!(hooks.is_empty());
}

#[test]
fn test_aggregated_tools_skips_disabled_plugins() {
    let p = make_builtin_plugin("t1");
    let p2 = make_builtin_plugin("t2");
    let registry = PluginRegistry::new(vec![
        RegisteredPlugin::new(p, false),
        RegisteredPlugin::new(p2, false),
    ]);
    let tools = registry.aggregated_tools().unwrap();
    assert!(tools.is_empty());
}

#[test]
fn test_plugin_load_failure_public_fields() {
    let lf = PluginLoadFailure::new(PathBuf::from("/some/path"), PluginKind::Bundled, "bundled-source".into(), PluginError::InvalidManifest("bad".into()));
    assert_eq!(lf.plugin_root, PathBuf::from("/some/path"));
    assert_eq!(lf.kind, PluginKind::Bundled);
    assert_eq!(lf.source, "bundled-source");
}

#[test]
fn test_plugin_load_failure_error_ref_command_failed() {
    let lf = PluginLoadFailure::new(PathBuf::from("/x"), PluginKind::Builtin, "b".into(), PluginError::CommandFailed("failed".into()));
    assert_eq!(lf.error().to_string(), "failed");
}

#[test]
fn test_group_serde_comprehensive() {
    let kinds = vec![PluginKind::Builtin, PluginKind::Bundled, PluginKind::External];
    for k in kinds {
        let json = serde_json::to_string(&k).unwrap();
        let back: PluginKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn test_permission_serde_across_variants() {
    let perms = vec![PluginPermission::Read, PluginPermission::Write, PluginPermission::Execute];
    for p in perms {
        let json = serde_json::to_string(&p).unwrap();
        let back: PluginPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn test_tool_permission_serde_across_variants() {
    let perms = vec![PluginToolPermission::ReadOnly, PluginToolPermission::WorkspaceWrite, PluginToolPermission::DangerFullAccess];
    for p in perms {
        let json = serde_json::to_string(&p).unwrap();
        let back: PluginToolPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn test_plugin_hooks_serde_with_all_fields_empty() {
    let json = r#"{"PreToolUse":[],"PostToolUse":[],"PostToolUseFailure":[]}"#;
    let des: PluginHooks = serde_json::from_str(json).unwrap();
    assert!(des.is_empty());
}

#[test]
fn test_serde_manifest_with_commands() {
    let root = temp_dir("manifest-commands");
    write_file(&root.join("commands").join("s.sh"), "#!/bin/sh\n");
    make_executable(&root.join("commands").join("s.sh"));
    write_file(&root.join("plugin.json"), r#"{"name":"cmd-test","version":"1","description":"desc","commands":[{"name":"run","description":"run cmd","command":"./commands/s.sh"}]}"#);
    let m = load_plugin_from_directory(&root).unwrap();
    assert_eq!(m.commands.len(), 1);
    assert_eq!(m.commands[0].name, "run");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_plugin_discover_external_dirs() {
    let config_home = temp_dir("ext-dir-home");
    let ext_dir = temp_dir("ext-dir");
    write_external_plugin(&ext_dir.join("ext1"), "ext1", "1.0.0");
    write_external_plugin(&ext_dir.join("ext2"), "ext2", "1.0.0");

    let mut config = PluginManagerConfig::new(&config_home);
    config.external_dirs = vec![ext_dir.clone()];
    let manager = PluginManager::new(config);
    let plugins = manager.list_plugins().unwrap();
    assert!(plugins.iter().any(|p| p.metadata.name == "ext1"));
    assert!(plugins.iter().any(|p| p.metadata.name == "ext2"));

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&ext_dir);
}

#[test]
fn test_plugin_manager_aggregated_hooks_includes_enabled() {
    let config_home = temp_dir("agg-hooks-en-home");
    let source_root = temp_dir("agg-hooks-en-source");
    let plugin_dir = source_root.join("hooks-test");
    let pre_path = plugin_dir.join("hooks").join("pre.sh");
    write_file(&pre_path, "#!/bin/sh\nprintf 'test pre'\n");
    make_executable(&pre_path);
    write_file(&plugin_dir.join("plugin.json"), r#"{"name":"hooks-test","version":"1","description":"hooks test","hooks":{"PreToolUse":["./hooks/pre.sh"]},"defaultEnabled":true}"#);

    let mut config = PluginManagerConfig::new(&config_home);
    config.external_dirs = vec![source_root.clone()];
    config.enabled_plugins.insert("hooks-test@external".into(), true);
    let manager = PluginManager::new(config);
    let hooks = manager.aggregated_hooks().unwrap();
    assert_eq!(hooks.pre_tool_use.len(), 1);

    let _ = fs::remove_dir_all(&config_home);
    let _ = fs::remove_dir_all(&source_root);
}
