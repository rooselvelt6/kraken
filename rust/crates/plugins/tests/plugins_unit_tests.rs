use plugins::{
    HookEvent, HookRunResult, HookRunner, Plugin, PluginCommandManifest, PluginDefinition,
    PluginError, PluginHooks, PluginInstallSource, PluginKind, PluginLifecycle, PluginManager,
    PluginManagerConfig, PluginManifest, PluginManifestValidationError, PluginMetadata,
    PluginPermission, PluginRegistry, PluginRegistryReport, PluginSummary, PluginToolDefinition,
    PluginToolManifest, PluginToolPermission, RegisteredPlugin,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn make_builtin() -> PluginDefinition {
    plugins::builtin_plugins().into_iter().next().unwrap()
}

fn make_builtin_registered(enabled: bool) -> RegisteredPlugin {
    RegisteredPlugin::new(make_builtin(), enabled)
}

#[test]
fn plugin_hooks_default_is_empty() {
    assert!(PluginHooks::default().is_empty());
}

#[test]
fn plugin_hooks_not_empty_when_pre_populated() {
    let hooks = PluginHooks {
        pre_tool_use: vec!["cmd".to_string()],
        ..Default::default()
    };
    assert!(!hooks.is_empty());
}

#[test]
fn plugin_hooks_not_empty_when_post_populated() {
    let hooks = PluginHooks {
        post_tool_use: vec!["cmd".to_string()],
        ..Default::default()
    };
    assert!(!hooks.is_empty());
}

#[test]
fn plugin_hooks_not_empty_when_failure_populated() {
    let hooks = PluginHooks {
        post_tool_use_failure: vec!["cmd".to_string()],
        ..Default::default()
    };
    assert!(!hooks.is_empty());
}

#[test]
fn plugin_hooks_merged_with_empty() {
    let a = PluginHooks {
        pre_tool_use: vec!["a".to_string()],
        ..Default::default()
    };
    let b = PluginHooks::default();
    let merged = a.merged_with(&b);
    assert_eq!(merged.pre_tool_use, vec!["a"]);
}

#[test]
fn plugin_hooks_merged_with_both_populated() {
    let a = PluginHooks {
        pre_tool_use: vec!["a1".to_string()],
        post_tool_use: vec!["a2".to_string()],
        post_tool_use_failure: vec!["a3".to_string()],
    };
    let b = PluginHooks {
        pre_tool_use: vec!["b1".to_string()],
        post_tool_use: vec!["b2".to_string()],
        post_tool_use_failure: vec!["b3".to_string()],
    };
    let merged = a.merged_with(&b);
    assert_eq!(merged.pre_tool_use, vec!["a1", "b1"]);
    assert_eq!(merged.post_tool_use, vec!["a2", "b2"]);
    assert_eq!(merged.post_tool_use_failure, vec!["a3", "b3"]);
}

#[test]
fn plugin_hooks_merged_with_three() {
    let a = PluginHooks {
        pre_tool_use: vec!["a".to_string()],
        ..Default::default()
    };
    let b = PluginHooks {
        pre_tool_use: vec!["b".to_string()],
        ..Default::default()
    };
    let c = PluginHooks {
        pre_tool_use: vec!["c".to_string()],
        ..Default::default()
    };
    let merged = a.merged_with(&b).merged_with(&c);
    assert_eq!(merged.pre_tool_use, vec!["a", "b", "c"]);
}

#[test]
fn plugin_hooks_serde_roundtrip() {
    let hooks = PluginHooks {
        pre_tool_use: vec!["pre1".to_string(), "pre2".to_string()],
        post_tool_use: vec!["post1".to_string()],
        post_tool_use_failure: vec!["fail1".to_string()],
    };
    let json = serde_json::to_string(&hooks).unwrap();
    let deserialized: PluginHooks = serde_json::from_str(&json).unwrap();
    assert_eq!(hooks, deserialized);
}

#[test]
fn plugin_hooks_serde_uses_renamed_fields() {
    let json = r#"{"PreToolUse":["a"],"PostToolUse":["b"],"PostToolUseFailure":["c"]}"#;
    let hooks: PluginHooks = serde_json::from_str(json).unwrap();
    assert_eq!(hooks.pre_tool_use, vec!["a"]);
    assert_eq!(hooks.post_tool_use, vec!["b"]);
    assert_eq!(hooks.post_tool_use_failure, vec!["c"]);
}

#[test]
fn plugin_hooks_serde_defaults_missing_fields() {
    let json = r#"{}"#;
    let hooks: PluginHooks = serde_json::from_str(json).unwrap();
    assert!(hooks.is_empty());
}

#[test]
fn plugin_lifecycle_default_is_empty() {
    assert!(PluginLifecycle::default().is_empty());
}

#[test]
fn plugin_lifecycle_not_empty_when_init_populated() {
    let lc = PluginLifecycle {
        init: vec!["setup".to_string()],
        ..Default::default()
    };
    assert!(!lc.is_empty());
}

#[test]
fn plugin_lifecycle_not_empty_when_shutdown_populated() {
    let lc = PluginLifecycle {
        shutdown: vec!["teardown".to_string()],
        ..Default::default()
    };
    assert!(!lc.is_empty());
}

#[test]
fn plugin_lifecycle_serde_roundtrip() {
    let lc = PluginLifecycle {
        init: vec!["i1".to_string()],
        shutdown: vec!["s1".to_string()],
    };
    let json = serde_json::to_string(&lc).unwrap();
    let deserialized: PluginLifecycle = serde_json::from_str(&json).unwrap();
    assert_eq!(lc, deserialized);
}

#[test]
fn plugin_lifecycle_serde_uses_renamed_fields() {
    let json = r#"{"Init":["i"],"Shutdown":["s"]}"#;
    let lc: PluginLifecycle = serde_json::from_str(json).unwrap();
    assert_eq!(lc.init, vec!["i"]);
    assert_eq!(lc.shutdown, vec!["s"]);
}

#[test]
fn plugin_permission_as_str_read() {
    assert_eq!(PluginPermission::Read.as_str(), "read");
}

#[test]
fn plugin_permission_as_str_write() {
    assert_eq!(PluginPermission::Write.as_str(), "write");
}

#[test]
fn plugin_permission_as_str_execute() {
    assert_eq!(PluginPermission::Execute.as_str(), "execute");
}

#[test]
fn plugin_permission_as_ref() {
    let perm = PluginPermission::Read;
    let s: &str = perm.as_ref();
    assert_eq!(s, "read");
}

#[test]
fn plugin_permission_serde_roundtrip() {
    let perms = vec![PluginPermission::Read, PluginPermission::Write, PluginPermission::Execute];
    let json = serde_json::to_string(&perms).unwrap();
    let deserialized: Vec<PluginPermission> = serde_json::from_str(&json).unwrap();
    assert_eq!(perms, deserialized);
}

#[test]
fn plugin_tool_permission_as_str_read_only() {
    assert_eq!(PluginToolPermission::ReadOnly.as_str(), "read-only");
}

#[test]
fn plugin_tool_permission_as_str_workspace_write() {
    assert_eq!(PluginToolPermission::WorkspaceWrite.as_str(), "workspace-write");
}

#[test]
fn plugin_tool_permission_as_str_danger_full_access() {
    assert_eq!(PluginToolPermission::DangerFullAccess.as_str(), "danger-full-access");
}

#[test]
fn plugin_tool_permission_serde_roundtrip() {
    let perms = vec![
        PluginToolPermission::ReadOnly,
        PluginToolPermission::WorkspaceWrite,
        PluginToolPermission::DangerFullAccess,
    ];
    let json = serde_json::to_string(&perms).unwrap();
    let deserialized: Vec<PluginToolPermission> = serde_json::from_str(&json).unwrap();
    assert_eq!(perms, deserialized);
}

#[test]
fn plugin_tool_permission_serde_uses_kebab_case() {
    let json = r#""read-only""#;
    let perm: PluginToolPermission = serde_json::from_str(json).unwrap();
    assert_eq!(perm, PluginToolPermission::ReadOnly);
    let json2 = r#""workspace-write""#;
    let perm2: PluginToolPermission = serde_json::from_str(json2).unwrap();
    assert_eq!(perm2, PluginToolPermission::WorkspaceWrite);
    let json3 = r#""danger-full-access""#;
    let perm3: PluginToolPermission = serde_json::from_str(json3).unwrap();
    assert_eq!(perm3, PluginToolPermission::DangerFullAccess);
}

#[test]
fn plugin_tool_manifest_serde_roundtrip() {
    let tool = PluginToolManifest {
        name: "my_tool".to_string(),
        description: "desc".to_string(),
        input_schema: json!({"type": "object"}),
        command: "./run.sh".to_string(),
        args: vec!["--flag".to_string()],
        required_permission: PluginToolPermission::WorkspaceWrite,
    };
    let json = serde_json::to_string(&tool).unwrap();
    let deserialized: PluginToolManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(tool, deserialized);
}

#[test]
fn plugin_command_manifest_serde_roundtrip() {
    let cmd = PluginCommandManifest {
        name: "sync".to_string(),
        description: "sync desc".to_string(),
        command: "./sync.sh".to_string(),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: PluginCommandManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(cmd, deserialized);
}

#[test]
fn plugin_tool_definition_serde_roundtrip() {
    let def = PluginToolDefinition {
        name: "tool_name".to_string(),
        description: Some("a tool".to_string()),
        input_schema: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
    };
    let json = serde_json::to_string(&def).unwrap();
    let deserialized: PluginToolDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(def, deserialized);
}

#[test]
fn plugin_tool_definition_serde_with_none_description() {
    let def = PluginToolDefinition {
        name: "t".to_string(),
        description: None,
        input_schema: json!({}),
    };
    let json = serde_json::to_string(&def).unwrap();
    let deserialized: PluginToolDefinition = serde_json::from_str(&json).unwrap();
    assert!(deserialized.description.is_none());
}

#[test]
fn plugin_tool_definition_serde_with_input_schema_nested() {
    let def = PluginToolDefinition {
        name: "nested".to_string(),
        description: Some("d".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"}
                    }
                }
            }
        }),
    };
    let json = serde_json::to_string(&def).unwrap();
    let deserialized: PluginToolDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(def, deserialized);
}

#[test]
fn plugin_manifest_serde_roundtrip_minimal() {
    let manifest = PluginManifest {
        name: "test".to_string(),
        version: "1.0.0".to_string(),
        description: "desc".to_string(),
        permissions: vec![],
        default_enabled: false,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, deserialized);
}

#[test]
fn plugin_manifest_serde_roundtrip_full() {
    let manifest = PluginManifest {
        name: "full".to_string(),
        version: "2.0.0".to_string(),
        description: "full plugin".to_string(),
        permissions: vec![PluginPermission::Read, PluginPermission::Write],
        default_enabled: true,
        hooks: PluginHooks {
            pre_tool_use: vec!["pre".to_string()],
            post_tool_use: vec!["post".to_string()],
            post_tool_use_failure: vec!["fail".to_string()],
        },
        lifecycle: PluginLifecycle {
            init: vec!["init".to_string()],
            shutdown: vec!["shutdown".to_string()],
        },
        tools: vec![PluginToolManifest {
            name: "tool1".to_string(),
            description: "tool1 desc".to_string(),
            input_schema: json!({"type": "object"}),
            command: "./tool.sh".to_string(),
            args: vec![],
            required_permission: PluginToolPermission::ReadOnly,
        }],
        commands: vec![PluginCommandManifest {
            name: "cmd1".to_string(),
            description: "cmd1 desc".to_string(),
            command: "./cmd.sh".to_string(),
        }],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, deserialized);
}

#[test]
fn plugin_manifest_serde_uses_default_enabled_field() {
    let manifest = PluginManifest {
        name: "test".to_string(),
        version: "1.0.0".to_string(),
        description: "desc".to_string(),
        permissions: vec![],
        default_enabled: true,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(json.contains("defaultEnabled"));
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert!(deserialized.default_enabled);
}

#[test]
fn plugin_manifest_serde_roundtrip_multiple_tools_and_commands() {
    let manifest = PluginManifest {
        name: "multi".to_string(),
        version: "1.0.0".to_string(),
        description: "multi".to_string(),
        permissions: vec![PluginPermission::Read, PluginPermission::Execute],
        default_enabled: false,
        hooks: PluginHooks {
            pre_tool_use: vec!["h1".to_string(), "h2".to_string()],
            post_tool_use: vec![],
            post_tool_use_failure: vec![],
        },
        lifecycle: PluginLifecycle::default(),
        tools: vec![
            PluginToolManifest {
                name: "t1".to_string(),
                description: "d1".to_string(),
                input_schema: json!({"type": "object"}),
                command: "c1".to_string(),
                args: vec!["a".to_string()],
                required_permission: PluginToolPermission::ReadOnly,
            },
            PluginToolManifest {
                name: "t2".to_string(),
                description: "d2".to_string(),
                input_schema: json!({"type": "object"}),
                command: "c2".to_string(),
                args: vec![],
                required_permission: PluginToolPermission::DangerFullAccess,
            },
        ],
        commands: vec![
            PluginCommandManifest { name: "c1".to_string(), description: "d".to_string(), command: "cmd1".to_string() },
            PluginCommandManifest { name: "c2".to_string(), description: "d".to_string(), command: "cmd2".to_string() },
        ],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.tools.len(), 2);
    assert_eq!(deserialized.tools.len(), 2);
    assert_eq!(manifest.commands.len(), 2);
    assert_eq!(deserialized.commands.len(), 2);
}

#[test]
fn plugin_manifest_serde_multiple_permissions() {
    let manifest = PluginManifest {
        name: "p".to_string(),
        version: "1".to_string(),
        description: "d".to_string(),
        permissions: vec![PluginPermission::Read, PluginPermission::Write, PluginPermission::Execute],
        default_enabled: false,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.permissions.len(), 3);
}

#[test]
fn plugin_manifest_lifecycle_serde_roundtrip() {
    let manifest = PluginManifest {
        name: "lc".to_string(),
        version: "1".to_string(),
        description: "d".to_string(),
        permissions: vec![],
        default_enabled: false,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle {
            init: vec!["init.sh".to_string()],
            shutdown: vec!["shutdown.sh".to_string()],
        },
        tools: vec![],
        commands: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.lifecycle.init, vec!["init.sh"]);
    assert_eq!(deserialized.lifecycle.shutdown, vec!["shutdown.sh"]);
}

#[test]
fn plugin_manifest_serde_hooks_roundtrip_in_manifest() {
    let manifest = PluginManifest {
        name: "h".to_string(),
        version: "1".to_string(),
        description: "d".to_string(),
        permissions: vec![],
        default_enabled: false,
        hooks: PluginHooks {
            pre_tool_use: vec!["pre".to_string()],
            post_tool_use: vec!["post".to_string()],
            post_tool_use_failure: vec!["fail".to_string()],
        },
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.hooks.pre_tool_use, vec!["pre"]);
    assert_eq!(deserialized.hooks.post_tool_use, vec!["post"]);
    assert_eq!(deserialized.hooks.post_tool_use_failure, vec!["fail"]);
}

#[test]
fn plugin_manifest_serde_default_hooks_in_manifest() {
    let json = r#"{"name":"t","version":"1","description":"d","permissions":[],"hooks":{}}"#;
    let manifest: PluginManifest = serde_json::from_str(json).unwrap();
    assert!(manifest.hooks.is_empty());
    assert!(manifest.tools.is_empty());
    assert!(manifest.commands.is_empty());
}

#[test]
fn plugin_manifest_serde_default_lifecycle_in_manifest() {
    let json = r#"{"name":"t","version":"1","description":"d","permissions":[],"lifecycle":{}}"#;
    let manifest: PluginManifest = serde_json::from_str(json).unwrap();
    assert!(manifest.lifecycle.is_empty());
}

#[test]
fn plugin_manifest_serde_tool_with_input_schema_complex() {
    let manifest = PluginManifest {
        name: "t".to_string(),
        version: "1".to_string(),
        description: "d".to_string(),
        permissions: vec![],
        default_enabled: false,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![PluginToolManifest {
            name: "complex_tool".to_string(),
            description: "desc".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "count": {"type": "integer"},
                    "tags": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["name"]
            }),
            command: "run".to_string(),
            args: vec!["--name".to_string(), "{name}".to_string()],
            required_permission: PluginToolPermission::WorkspaceWrite,
        }],
        commands: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: PluginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.tools[0].args, vec!["--name", "{name}"]);
}

#[test]
fn plugin_tool_manifest_default_args() {
    let tool = PluginToolManifest {
        name: "t".to_string(),
        description: "d".to_string(),
        input_schema: json!({}),
        command: "c".to_string(),
        args: vec![],
        required_permission: PluginToolPermission::ReadOnly,
    };
    let json = serde_json::to_string(&tool).unwrap();
    let deserialized: PluginToolManifest = serde_json::from_str(&json).unwrap();
    assert!(deserialized.args.is_empty());
}

#[test]
fn plugin_kind_display_builtin() {
    assert_eq!(PluginKind::Builtin.to_string(), "builtin");
}

#[test]
fn plugin_kind_display_bundled() {
    assert_eq!(PluginKind::Bundled.to_string(), "bundled");
}

#[test]
fn plugin_kind_display_external() {
    assert_eq!(PluginKind::External.to_string(), "external");
}

#[test]
fn plugin_kind_serde_roundtrip() {
    let kinds = vec![PluginKind::Builtin, PluginKind::Bundled, PluginKind::External];
    let json = serde_json::to_string(&kinds).unwrap();
    let deserialized: Vec<PluginKind> = serde_json::from_str(&json).unwrap();
    assert_eq!(kinds, deserialized);
}

#[test]
fn plugin_kind_serde_uses_lowercase() {
    let json = r#""builtin""#;
    let kind: PluginKind = serde_json::from_str(json).unwrap();
    assert_eq!(kind, PluginKind::Builtin);
}

#[test]
fn plugin_kind_copy() {
    let k = PluginKind::External;
    let k2 = k;
    assert_eq!(k, k2);
}

#[test]
fn plugin_permission_copy() {
    let p = PluginPermission::Write;
    let p2 = p;
    assert_eq!(p, p2);
}

#[test]
fn plugin_permission_ord() {
    assert!(PluginPermission::Read < PluginPermission::Write);
    assert!(PluginPermission::Write < PluginPermission::Execute);
}

#[test]
fn plugin_tool_permission_copy() {
    let p = PluginToolPermission::ReadOnly;
    let p2 = p;
    assert_eq!(p, p2);
}

#[test]
fn plugin_tool_permission_ord() {
    assert!(PluginToolPermission::ReadOnly < PluginToolPermission::WorkspaceWrite);
    assert!(PluginToolPermission::WorkspaceWrite < PluginToolPermission::DangerFullAccess);
}

#[test]
fn plugin_install_source_serde_roundtrip_local() {
    let source = PluginInstallSource::LocalPath {
        path: PathBuf::from("/tmp/plugin"),
    };
    let json = serde_json::to_string(&source).unwrap();
    let deserialized: PluginInstallSource = serde_json::from_str(&json).unwrap();
    assert_eq!(source, deserialized);
}

#[test]
fn plugin_install_source_serde_roundtrip_git() {
    let source = PluginInstallSource::GitUrl {
        url: "https://github.com/example/plugin.git".to_string(),
    };
    let json = serde_json::to_string(&source).unwrap();
    assert!(json.contains("git_url"));
    let deserialized: PluginInstallSource = serde_json::from_str(&json).unwrap();
    assert_eq!(source, deserialized);
}

#[test]
fn plugin_install_source_serde_uses_tagged() {
    let json = r#"{"type":"local_path","path":"/tmp/test"}"#;
    let source: PluginInstallSource = serde_json::from_str(json).unwrap();
    match source {
        PluginInstallSource::LocalPath { path } => assert_eq!(path, PathBuf::from("/tmp/test")),
        _ => panic!("expected LocalPath"),
    }
}

#[test]
fn installed_plugin_registry_default_is_empty() {
    let registry = PluginRegistry::default();
    assert!(registry.plugins().is_empty());
}

#[test]
fn installed_plugin_registry_serde_roundtrip() {
    let mut plugins = BTreeMap::new();
    plugins.insert(
        "test-plugin".to_string(),
        plugins::InstalledPluginRecord {
            kind: PluginKind::External,
            id: "test-plugin".to_string(),
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            install_path: PathBuf::from("/tmp/test"),
            source: PluginInstallSource::LocalPath { path: PathBuf::from("/src") },
            installed_at_unix_ms: 1000,
            updated_at_unix_ms: 2000,
        },
    );
    let registry = plugins::InstalledPluginRegistry { plugins };
    let json = serde_json::to_string(&registry).unwrap();
    let deserialized: plugins::InstalledPluginRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(registry, deserialized);
}

#[test]
fn installed_plugin_registry_serde_default_kind() {
    let json = r#"{"plugins":{"p":{"id":"p","name":"p","version":"1","description":"d","install_path":"/tmp","source":{"type":"local_path","path":"/tmp"},"installed_at_unix_ms":0,"updated_at_unix_ms":0}}}"#;
    let registry: plugins::InstalledPluginRegistry = serde_json::from_str(json).unwrap();
    assert_eq!(
        registry.plugins.get("p").unwrap().kind,
        PluginKind::External
    );
}

#[test]
fn installed_plugin_registry_default_partial_eq() {
    let a = plugins::InstalledPluginRegistry::default();
    let b = plugins::InstalledPluginRegistry::default();
    assert_eq!(a, b);
}

#[test]
fn installed_plugin_record_serde_roundtrip() {
    let record = plugins::InstalledPluginRecord {
        kind: PluginKind::Bundled,
        id: "test@bundled".to_string(),
        name: "test".to_string(),
        version: "1.0.0".to_string(),
        description: "d".to_string(),
        install_path: PathBuf::from("/tmp/test"),
        source: PluginInstallSource::GitUrl {
            url: "https://example.com".to_string(),
        },
        installed_at_unix_ms: 12345,
        updated_at_unix_ms: 67890,
    };
    let json = serde_json::to_string(&record).unwrap();
    let deserialized: plugins::InstalledPluginRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, deserialized);
}

#[test]
fn plugin_registry_new_sorts_by_id() {
    let p1 = make_builtin_registered(true);
    let registry = PluginRegistry::new(vec![p1]);
    let ids: Vec<_> = registry.plugins().iter().map(|p| p.metadata().id.as_str()).collect();
    assert_eq!(ids.len(), 1);
}

#[test]
fn plugin_registry_get_existing() {
    let def = make_builtin();
    let id = def.metadata().id.clone();
    let p = RegisteredPlugin::new(def, true);
    let registry = PluginRegistry::new(vec![p]);
    assert!(registry.get(&id).is_some());
}

#[test]
fn plugin_registry_get_nonexistent() {
    let registry = PluginRegistry::new(vec![]);
    assert!(registry.get("missing@ext").is_none());
}

#[test]
fn plugin_registry_contains_existing() {
    let def = make_builtin();
    let id = def.metadata().id.clone();
    let p = RegisteredPlugin::new(def, true);
    let registry = PluginRegistry::new(vec![p]);
    assert!(registry.contains(&id));
}

#[test]
fn plugin_registry_contains_nonexistent() {
    let registry = PluginRegistry::new(vec![]);
    assert!(!registry.contains("y@ext"));
}

#[test]
fn plugin_registry_summaries_count() {
    let p1 = make_builtin_registered(true);
    let p2 = make_builtin_registered(false);
    let registry = PluginRegistry::new(vec![p1, p2]);
    assert_eq!(registry.summaries().len(), 2);
}

#[test]
fn plugin_registry_aggregated_hooks_empty_when_no_plugins() {
    let registry = PluginRegistry::new(vec![]);
    let hooks = registry.aggregated_hooks().unwrap();
    assert!(hooks.is_empty());
}

#[test]
fn plugin_registry_aggregated_tools_empty() {
    let registry = PluginRegistry::new(vec![]);
    let tools = registry.aggregated_tools().unwrap();
    assert!(tools.is_empty());
}

#[test]
fn hook_run_result_allow() {
    let result = HookRunResult::allow(vec!["msg".to_string()]);
    assert!(!result.is_denied());
    assert!(!result.is_failed());
    assert_eq!(result.messages(), &["msg"]);
}

#[test]
fn hook_run_result_allow_empty() {
    let result = HookRunResult::allow(vec![]);
    assert!(!result.is_denied());
    assert!(!result.is_failed());
    assert!(result.messages().is_empty());
}

#[test]
fn hook_run_result_clone() {
    let result = HookRunResult::allow(vec!["msg".to_string()]);
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn hook_runner_new_default_hooks() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(!result.is_denied());
    assert!(!result.is_failed());
}

#[test]
fn hook_runner_empty_hooks_returns_empty_messages() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(result.messages().is_empty());
}

#[test]
fn hook_runner_post_tool_use_empty_hooks() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_post_tool_use("tool", "{}", "output", false);
    assert!(!result.is_denied());
    assert!(!result.is_failed());
}

#[test]
fn hook_runner_post_tool_use_failure_empty_hooks() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_post_tool_use_failure("tool", "{}", "error");
    assert!(!result.is_denied());
    assert!(!result.is_failed());
}

#[test]
fn hook_event_as_str() {
    assert_eq!(format!("{:?}", HookEvent::PreToolUse), "PreToolUse");
    assert_eq!(format!("{:?}", HookEvent::PostToolUse), "PostToolUse");
    assert_eq!(format!("{:?}", HookEvent::PostToolUseFailure), "PostToolUseFailure");
}

#[test]
fn hook_runner_from_registry_empty() {
    let registry = PluginRegistry::new(vec![]);
    let runner = HookRunner::from_registry(&registry).unwrap();
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(result.messages().is_empty());
}

#[test]
fn hook_runner_from_registry_with_builtin() {
    let p = make_builtin_registered(true);
    let registry = PluginRegistry::new(vec![p]);
    let runner = HookRunner::from_registry(&registry).unwrap();
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(!result.is_denied());
}

#[test]
fn hook_runner_with_literal_command() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["printf 'hello world'".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(!result.is_denied());
    assert!(!result.is_failed());
    assert_eq!(result.messages(), &["hello world"]);
}

#[test]
fn hook_runner_deny_command() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["exit 2".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(result.is_denied());
}

#[test]
fn hook_runner_fail_command() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["exit 1".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(result.is_failed());
}

#[test]
fn hook_runner_deny_with_message() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["printf 'blocked'; exit 2".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Read", "{}");
    assert!(result.is_denied());
    assert!(result.messages().iter().any(|m| m.contains("blocked")));
}

#[test]
fn hook_runner_fail_with_message() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["printf 'broken'; exit 1".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("Bash", "{}");
    assert!(result.is_failed());
    assert!(result.messages().iter().any(|m| m.contains("broken")));
}

#[test]
fn hook_runner_multiple_commands_first_deny_stops() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["exit 2".to_string(), "printf 'later'".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(result.is_denied());
    assert!(!result.messages().iter().any(|m| m.contains("later")));
}

#[test]
fn hook_runner_multiple_commands_first_fail_stops() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["exit 1".to_string(), "printf 'later'".to_string()],
        ..Default::default()
    });
    let result = runner.run_pre_tool_use("tool", "{}");
    assert!(result.is_failed());
    assert!(!result.messages().iter().any(|m| m.contains("later")));
}

#[test]
fn hook_runner_pre_tool_use_with_invalid_json_input() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_pre_tool_use("tool", "not json");
    assert!(!result.is_denied());
    assert!(!result.is_failed());
}

#[test]
fn hook_runner_post_tool_use_error_flag() {
    let runner = HookRunner::new(PluginHooks::default());
    let result = runner.run_post_tool_use("tool", "{}", "output", true);
    assert!(!result.is_denied());
    assert!(!result.is_failed());
}

#[test]
fn hook_runner_clone() {
    let runner = HookRunner::new(PluginHooks {
        pre_tool_use: vec!["cmd".to_string()],
        ..Default::default()
    });
    let cloned = runner.clone();
    let result = cloned.run_pre_tool_use("t", "{}");
    assert!(!result.is_denied());
}

#[test]
fn plugin_tool_construction() {
    let tool = plugins::PluginTool::new(
        "pid",
        "pname",
        PluginToolDefinition {
            name: "t".to_string(),
            description: Some("d".to_string()),
            input_schema: json!({"type": "object"}),
        },
        "echo",
        vec![],
        PluginToolPermission::ReadOnly,
        None,
    );
    assert_eq!(tool.plugin_id(), "pid");
    assert_eq!(tool.definition().name, "t");
    assert_eq!(tool.required_permission(), "read-only");
}

#[test]
fn plugin_tool_construction_with_args_and_root() {
    let tool = plugins::PluginTool::new(
        "pid",
        "pname",
        PluginToolDefinition {
            name: "t".to_string(),
            description: None,
            input_schema: json!({}),
        },
        "run",
        vec!["--verbose".to_string()],
        PluginToolPermission::DangerFullAccess,
        Some(PathBuf::from("/root")),
    );
    assert_eq!(tool.required_permission(), "danger-full-access");
}

#[test]
fn plugin_metadata_fields() {
    let meta = PluginMetadata {
        id: "test-id@ext".to_string(),
        name: "test-id".to_string(),
        version: "1.0.0".to_string(),
        description: "test plugin".to_string(),
        kind: PluginKind::External,
        source: "test".to_string(),
        default_enabled: false,
        root: None,
    };
    assert_eq!(meta.id, "test-id@ext");
    assert_eq!(meta.version, "1.0.0");
    assert_eq!(meta.kind, PluginKind::External);
}

#[test]
fn plugin_metadata_clone() {
    let meta = PluginMetadata {
        id: "clone-test@ext".to_string(),
        name: "clone-test".to_string(),
        version: "1.0.0".to_string(),
        description: "desc".to_string(),
        kind: PluginKind::External,
        source: "test".to_string(),
        default_enabled: false,
        root: None,
    };
    let cloned = meta.clone();
    assert_eq!(meta, cloned);
}

#[test]
fn plugin_summary_fields() {
    let meta = PluginMetadata {
        id: "summary-test@ext".to_string(),
        name: "summary-test".to_string(),
        version: "1.0.0".to_string(),
        description: "desc".to_string(),
        kind: PluginKind::External,
        source: "test".to_string(),
        default_enabled: false,
        root: None,
    };
    let summary = PluginSummary {
        metadata: meta.clone(),
        enabled: true,
    };
    assert_eq!(summary.metadata.id, "summary-test@ext");
    assert!(summary.enabled);
}

#[test]
fn plugin_summary_clone() {
    let meta = PluginMetadata {
        id: "s@ext".to_string(),
        name: "s".to_string(),
        version: "1.0.0".to_string(),
        description: "d".to_string(),
        kind: PluginKind::External,
        source: "test".to_string(),
        default_enabled: false,
        root: None,
    };
    let s = PluginSummary {
        metadata: meta,
        enabled: true,
    };
    let cloned = s.clone();
    assert_eq!(s, cloned);
}

#[test]
fn plugin_summary_partial_eq() {
    let meta = PluginMetadata {
        id: "s@ext".to_string(),
        name: "s".to_string(),
        version: "1.0.0".to_string(),
        description: "d".to_string(),
        kind: PluginKind::External,
        source: "test".to_string(),
        default_enabled: false,
        root: None,
    };
    let a = PluginSummary {
        metadata: meta.clone(),
        enabled: true,
    };
    let b = PluginSummary {
        metadata: meta,
        enabled: true,
    };
    assert_eq!(a, b);
}

#[test]
fn plugin_hooks_clone() {
    let hooks = PluginHooks {
        pre_tool_use: vec!["a".to_string()],
        post_tool_use: vec!["b".to_string()],
        post_tool_use_failure: vec!["c".to_string()],
    };
    let cloned = hooks.clone();
    assert_eq!(hooks, cloned);
}

#[test]
fn plugin_lifecycle_clone() {
    let lc = PluginLifecycle {
        init: vec!["i".to_string()],
        shutdown: vec!["s".to_string()],
    };
    let cloned = lc.clone();
    assert_eq!(lc, cloned);
}

#[test]
fn plugin_manifest_clone() {
    let manifest = PluginManifest {
        name: "test".to_string(),
        version: "1.0.0".to_string(),
        description: "d".to_string(),
        permissions: vec![PluginPermission::Read],
        default_enabled: true,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        tools: vec![],
        commands: vec![],
    };
    let cloned = manifest.clone();
    assert_eq!(manifest, cloned);
}

#[test]
fn registered_plugin_new() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.is_enabled());
}

#[test]
fn registered_plugin_disabled() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, false);
    assert!(!rp.is_enabled());
}

#[test]
fn registered_plugin_summary() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    let summary = rp.summary();
    assert!(summary.enabled);
}

#[test]
fn registered_plugin_validate_succeeds_for_builtin() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.validate().is_ok());
}

#[test]
fn registered_plugin_initialize_succeeds_for_builtin() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.initialize().is_ok());
}

#[test]
fn registered_plugin_shutdown_succeeds_for_builtin() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.shutdown().is_ok());
}

#[test]
fn registered_plugin_hooks_accessor() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.hooks().is_empty());
}

#[test]
fn registered_plugin_tools_accessor_empty() {
    let def = make_builtin();
    let rp = RegisteredPlugin::new(def, true);
    assert!(rp.tools().is_empty());
}

#[test]
fn plugin_registry_report_no_failures() {
    let registry = PluginRegistry::new(vec![]);
    let report = PluginRegistryReport::new(registry, vec![]);
    assert!(!report.has_failures());
    assert!(report.failures().is_empty());
    assert!(report.summaries().is_empty());
}

#[test]
fn plugin_registry_report_into_registry_succeeds() {
    let registry = PluginRegistry::new(vec![]);
    let report = PluginRegistryReport::new(registry, vec![]);
    assert!(report.into_registry().is_ok());
}

#[test]
fn plugin_registry_report_into_registry_fails_with_failures() {
    let failure = plugins::PluginLoadFailure::new(
        PathBuf::from("/tmp"),
        PluginKind::External,
        "test".to_string(),
        PluginError::NotFound("missing".to_string()),
    );
    let report = PluginRegistryReport::new(PluginRegistry::new(vec![]), vec![failure]);
    assert!(report.has_failures());
    assert!(report.into_registry().is_err());
}

#[test]
fn plugin_manager_config_new() {
    let config = PluginManagerConfig::new("/tmp/config");
    assert_eq!(config.config_home, PathBuf::from("/tmp/config"));
    assert!(config.enabled_plugins.is_empty());
    assert!(config.external_dirs.is_empty());
    assert!(config.install_root.is_none());
    assert!(config.registry_path.is_none());
    assert!(config.bundled_root.is_none());
}

#[test]
fn plugin_manager_config_with_all_fields() {
    let mut config = PluginManagerConfig::new("/home");
    config.install_root = Some(PathBuf::from("/install"));
    config.registry_path = Some(PathBuf::from("/registry.json"));
    config.bundled_root = Some(PathBuf::from("/bundled"));
    config.external_dirs = vec![PathBuf::from("/ext1"), PathBuf::from("/ext2")];
    config.enabled_plugins.insert("p1".to_string(), true);
    config.enabled_plugins.insert("p2".to_string(), false);
    assert_eq!(config.install_root.unwrap(), PathBuf::from("/install"));
    assert_eq!(config.registry_path.unwrap(), PathBuf::from("/registry.json"));
    assert_eq!(config.bundled_root.unwrap(), PathBuf::from("/bundled"));
    assert_eq!(config.external_dirs.len(), 2);
    assert_eq!(config.enabled_plugins.len(), 2);
}

#[test]
fn plugin_manager_config_clone() {
    let mut config = PluginManagerConfig::new("/cfg");
    config.enabled_plugins.insert("p1".to_string(), true);
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

#[test]
fn plugin_manager_config_partial_eq() {
    let a = PluginManagerConfig::new("/cfg");
    let b = PluginManagerConfig::new("/cfg");
    assert_eq!(a, b);
}

#[test]
fn plugin_manager_config_partial_ne() {
    let a = PluginManagerConfig::new("/cfg1");
    let b = PluginManagerConfig::new("/cfg2");
    assert_ne!(a, b);
}

#[test]
fn plugin_manager_config_bundled_root_some() {
    let mut config = PluginManagerConfig::new("/home");
    config.bundled_root = Some(PathBuf::from("/bundled"));
    let manager = PluginManager::new(config);
    assert!(manager.install_root().starts_with("/home"));
}

#[test]
fn plugin_manifest_validation_error_empty_field_display() {
    let err = PluginManifestValidationError::EmptyField { field: "name" };
    let msg = err.to_string();
    assert!(msg.contains("name"));
    assert!(msg.contains("cannot be empty"));
}

#[test]
fn plugin_manifest_validation_error_empty_entry_field_with_name_display() {
    let err = PluginManifestValidationError::EmptyEntryField {
        kind: "tool",
        field: "description",
        name: Some("my_tool".to_string()),
    };
    let msg = err.to_string();
    assert!(msg.contains("my_tool"));
    assert!(msg.contains("description"));
}

#[test]
fn plugin_manifest_validation_error_empty_entry_field_without_name_display() {
    let err = PluginManifestValidationError::EmptyEntryField {
        kind: "permission",
        field: "value",
        name: None,
    };
    let msg = err.to_string();
    assert!(msg.contains("permission"));
    assert!(msg.contains("value"));
    assert!(msg.contains("cannot be empty"));
}

#[test]
fn plugin_manifest_validation_error_empty_entry_field_empty_name_display() {
    let err = PluginManifestValidationError::EmptyEntryField {
        kind: "hook",
        field: "command",
        name: Some(String::new()),
    };
    let msg = err.to_string();
    assert!(msg.contains("hook"));
    assert!(msg.contains("cannot be empty"));
}

#[test]
fn plugin_manifest_validation_error_invalid_permission_display() {
    let err = PluginManifestValidationError::InvalidPermission {
        permission: "admin".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("admin"));
    assert!(msg.contains("read, write, or execute"));
}

#[test]
fn plugin_manifest_validation_error_duplicate_permission_display() {
    let err = PluginManifestValidationError::DuplicatePermission {
        permission: "read".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("read"));
    assert!(msg.contains("duplicated"));
}

#[test]
fn plugin_manifest_validation_error_duplicate_entry_display() {
    let err = PluginManifestValidationError::DuplicateEntry {
        kind: "tool",
        name: "my_tool".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("my_tool"));
    assert!(msg.contains("tool"));
    assert!(msg.contains("duplicated"));
}

#[test]
fn plugin_manifest_validation_error_missing_path_display() {
    let err = PluginManifestValidationError::MissingPath {
        kind: "hook",
        path: PathBuf::from("/hooks/pre.sh"),
    };
    let msg = err.to_string();
    assert!(msg.contains("does not exist"));
    assert!(msg.contains("pre.sh"));
}

#[test]
fn plugin_manifest_validation_error_path_is_directory_display() {
    let err = PluginManifestValidationError::PathIsDirectory {
        kind: "tool",
        path: PathBuf::from("/tools/dir"),
    };
    let msg = err.to_string();
    assert!(msg.contains("must point to a file"));
    assert!(msg.contains("dir"));
}

#[test]
fn plugin_manifest_validation_error_invalid_tool_input_schema_display() {
    let err = PluginManifestValidationError::InvalidToolInputSchema {
        tool_name: "my_tool".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("my_tool"));
    assert!(msg.contains("inputSchema"));
}

#[test]
fn plugin_manifest_validation_error_invalid_tool_required_permission_display() {
    let err = PluginManifestValidationError::InvalidToolRequiredPermission {
        tool_name: "t".to_string(),
        permission: "invalid".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("t"));
    assert!(msg.contains("invalid"));
}

#[test]
fn plugin_manifest_validation_error_unsupported_manifest_contract_display() {
    let err = PluginManifestValidationError::UnsupportedManifestContract {
        detail: "not supported".to_string(),
    };
    assert_eq!(err.to_string(), "not supported");
}

#[test]
fn plugin_error_display_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let err = PluginError::Io(io_err);
    let msg = err.to_string();
    assert!(msg.contains("file missing"));
}

#[test]
fn plugin_error_display_invalid_manifest() {
    let err = PluginError::InvalidManifest("bad manifest".to_string());
    assert_eq!(err.to_string(), "bad manifest");
}

#[test]
fn plugin_error_display_not_found() {
    let err = PluginError::NotFound("missing".to_string());
    assert_eq!(err.to_string(), "missing");
}

#[test]
fn plugin_error_display_command_failed() {
    let err = PluginError::CommandFailed("cmd failed".to_string());
    assert_eq!(err.to_string(), "cmd failed");
}

#[test]
fn plugin_error_display_manifest_validation() {
    let errors = vec![
        PluginManifestValidationError::EmptyField { field: "name" },
        PluginManifestValidationError::EmptyField { field: "version" },
    ];
    let err = PluginError::ManifestValidation(errors);
    let msg = err.to_string();
    assert!(msg.contains("name"));
    assert!(msg.contains("; "));
    assert!(msg.contains("version"));
}

#[test]
fn plugin_error_display_load_failures() {
    let failure = plugins::PluginLoadFailure::new(
        PathBuf::from("/tmp"),
        PluginKind::External,
        "test".to_string(),
        PluginError::NotFound("missing".to_string()),
    );
    let err = PluginError::LoadFailures(vec![failure]);
    let msg = err.to_string();
    assert!(msg.contains("failed to load"));
}

#[test]
fn plugin_error_json_display() {
    let json_err = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
    let err = PluginError::Json(json_err);
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn plugin_error_manifest_validation_multiple_variants() {
    let errors = vec![
        PluginManifestValidationError::EmptyField { field: "name" },
        PluginManifestValidationError::InvalidPermission { permission: "bad".to_string() },
        PluginManifestValidationError::DuplicateEntry { kind: "tool", name: "t".to_string() },
        PluginManifestValidationError::MissingPath { kind: "hook", path: PathBuf::from("/p") },
    ];
    let err = PluginError::ManifestValidation(errors);
    let msg = err.to_string();
    assert!(msg.contains("name"));
    assert!(msg.contains("bad"));
    assert!(msg.contains("t"));
    assert!(msg.contains("does not exist"));
}

#[test]
fn plugin_error_is_std_error() {
    let err = PluginError::NotFound("test".to_string());
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn plugin_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "io problem");
    let err: PluginError = io_err.into();
    assert!(matches!(err, PluginError::Io(_)));
}

#[test]
fn plugin_error_from_json_error() {
    let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
    let err: PluginError = json_err.into();
    assert!(matches!(err, PluginError::Json(_)));
}

#[test]
fn plugin_error_debug() {
    let err = PluginError::NotFound("test".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("NotFound"));
}

#[test]
fn plugin_load_failure_display() {
    let failure = plugins::PluginLoadFailure::new(
        PathBuf::from("/my/plugin"),
        PluginKind::External,
        "source_url".to_string(),
        PluginError::NotFound("manifest missing".to_string()),
    );
    let msg = failure.to_string();
    assert!(msg.contains("external"));
    assert!(msg.contains("source_url"));
}

#[test]
fn plugin_load_failure_error_ref() {
    let failure = plugins::PluginLoadFailure::new(
        PathBuf::from("/p"),
        PluginKind::Bundled,
        "s".to_string(),
        PluginError::NotFound("x".to_string()),
    );
    assert!(matches!(failure.error(), PluginError::NotFound(_)));
}

#[test]
fn builtin_plugins_count() {
    let builtins = plugins::builtin_plugins();
    assert_eq!(builtins.len(), 1);
}

#[test]
fn builtin_plugins_metadata() {
    let builtins = plugins::builtin_plugins();
    let def = &builtins[0];
    assert_eq!(def.metadata().id, "example-builtin@builtin");
    assert_eq!(def.metadata().kind, PluginKind::Builtin);
    assert_eq!(def.metadata().version, "0.1.0");
    assert!(!def.metadata().default_enabled);
}

#[test]
fn builtin_plugins_hooks_empty() {
    let builtins = plugins::builtin_plugins();
    assert!(builtins[0].hooks().is_empty());
}

#[test]
fn builtin_plugins_lifecycle_empty() {
    let builtins = plugins::builtin_plugins();
    assert!(builtins[0].lifecycle().is_empty());
}

#[test]
fn builtin_plugins_tools_empty() {
    let builtins = plugins::builtin_plugins();
    assert!(builtins[0].tools().is_empty());
}

#[test]
fn builtin_plugins_validate_succeeds() {
    let builtins = plugins::builtin_plugins();
    assert!(builtins[0].validate().is_ok());
}

#[test]
fn builtin_plugins_initialize_succeeds() {
    let builtins = plugins::builtin_plugins();
    assert!(builtins[0].initialize().is_ok());
}

#[test]
fn builtin_plugins_shutdown_succeeds() {
    let builtins = plugins::builtin_plugins();
    assert!(builtins[0].shutdown().is_ok());
}

#[test]
fn hook_event_debug() {
    let event = HookEvent::PreToolUse;
    assert_eq!(format!("{:?}", event), "PreToolUse");
}

#[test]
fn hook_run_result_debug() {
    let result = HookRunResult::allow(vec![]);
    let debug = format!("{:?}", result);
    assert!(debug.contains("HookRunResult"));
}

#[test]
fn plugin_registry_default_partial_eq() {
    let a = PluginRegistry::default();
    let b = PluginRegistry::default();
    assert_eq!(a, b);
}

#[test]
fn plugin_registry_debug() {
    let registry = PluginRegistry::default();
    let debug = format!("{:?}", registry);
    assert!(debug.contains("PluginRegistry"));
}

#[test]
fn plugin_manifest_validation_error_debug() {
    let err = PluginManifestValidationError::EmptyField { field: "x" };
    let debug = format!("{:?}", err);
    assert!(debug.contains("EmptyField"));
}

#[test]
fn plugin_registry_new_single_plugin() {
    let p = make_builtin_registered(true);
    let registry = PluginRegistry::new(vec![p]);
    assert_eq!(registry.plugins().len(), 1);
}

#[test]
fn plugin_manager_install_root_default() {
    let config = PluginManagerConfig::new("/home");
    let manager = PluginManager::new(config);
    let root = manager.install_root();
    assert!(root.starts_with("/home"));
    assert!(root.to_string_lossy().contains("plugins"));
}

#[test]
fn plugin_manager_registry_path_default() {
    let config = PluginManagerConfig::new("/home");
    let manager = PluginManager::new(config);
    let path = manager.registry_path();
    assert!(path.to_string_lossy().contains("installed.json"));
}

#[test]
fn plugin_manager_settings_path() {
    let config = PluginManagerConfig::new("/home");
    let manager = PluginManager::new(config);
    let path = manager.settings_path();
    assert!(path.to_string_lossy().contains("settings"));
}
