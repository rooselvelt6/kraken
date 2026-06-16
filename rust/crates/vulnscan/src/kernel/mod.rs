pub mod kconfig;
pub mod patterns;
pub mod version;

use crate::{DiscoveryMethod, Finding, FindingStatus, Severity};
use chrono::Utc;
use std::path::Path;

pub struct KernelMitigationAuditor;

impl KernelMitigationAuditor {
    pub fn check_kconfig(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let checks = [
            ("CONFIG_RANDOMIZE_BASE", "KASLR (Kernel Address Space Layout Randomization)", Severity::High, "Disables KASLR — kernel addresses predictable, arbitrary code execution at ring0. Enable CONFIG_RANDOMIZE_BASE."),
            ("CONFIG_X86_SMAP", "SMAP (Supervisor Mode Access Prevention)", Severity::High, "Disables SMAP — kernel can access userspace pages directly, nullifying SMEP bypass protection. Enable CONFIG_X86_SMAP."),
            ("CONFIG_X86_SMEP", "SMEP (Supervisor Mode Execution Prevention)", Severity::High, "Disables SMEP — kernel can execute userspace code directly. Enable CONFIG_X86_SMEP."),
            ("CONFIG_PAGE_TABLE_ISOLATION", "KPTI (Kernel Page Table Isolation)", Severity::High, "Disables KPTI — Meltdown-style attacks possible. Enable CONFIG_PAGE_TABLE_ISOLATION."),
            ("CONFIG_STACKPROTECTOR", "Kernel Stack Canary", Severity::Medium, "Kernel stack buffer overflows exploitable without detection. Enable CONFIG_STACKPROTECTOR or CONFIG_STACKPROTECTOR_STRONG."),
            ("CONFIG_STACKPROTECTOR_STRONG", "Kernel Stack Canary (Strong)", Severity::Medium, "Stack canary coverage limited. Enable CONFIG_STACKPROTECTOR_STRONG for comprehensive stack protection."),
            ("CONFIG_FORTIFY_SOURCE", "FORTIFY_SOURCE (kernel)", Severity::Medium, "Weakens compile-time bounds checking in kernel. Enable CONFIG_FORTIFY_SOURCE."),
            ("CONFIG_HARDENED_USERCOPY", "HARDENED_USERCOPY", Severity::Medium, "Disables hardened usercopy — heap overflow via copy_to_user/copy_from_user possible. Enable CONFIG_HARDENED_USERCOPY."),
            ("CONFIG_SECURITY_DMESG_RESTRICT", "dmesg Restrictions", Severity::Low, "kptr_restrict may be visible via dmesg — kernel address leaks possible. Enable CONFIG_SECURITY_DMESG_RESTRICT."),
            ("CONFIG_KASAN", "KASAN (Kernel Address Sanitizer)", Severity::Low, "KASAN not enabled — kernel memory corruption bugs undetected at runtime. Enable for debugging."),
            ("CONFIG_KCSAN", "KCSAN (Kernel Concurrency Sanitizer)", Severity::Low, "KCSAN not enabled — kernel data races undetected at runtime. Enable for debugging."),
            ("CONFIG_BUG_ON_DATA_CORRUPTION", "BUG_ON_DATA_CORRUPTION", Severity::Medium, "Disables additional sanity checks on kernel memory. Enable CONFIG_BUG_ON_DATA_CORRUPTION."),
            ("CONFIG_SECURITY", "LSM (Linux Security Modules)", Severity::Medium, "LSM framework disabled — no SELinux, AppArmor, or Smack. Enable CONFIG_SECURITY."),
            ("CONFIG_SECURITY_SELINUX", "SELinux", Severity::Low, "SELinux disabled — no mandatory access control. Enable if required by policy."),
            ("CONFIG_SECURITY_APPARMOR", "AppArmor", Severity::Low, "AppArmor disabled — no mandatory access control. Enable if required by policy."),
        ];

        let config_upper = content.to_uppercase();

        for (config_name, display_name, severity, remediation) in &checks {
            let disabled_pattern = format!("# {} is not set", config_name);
            let enabled_pattern = format!("{}=y", config_name);
            let module_pattern = format!("{}=m", config_name);

            if config_upper.contains(&disabled_pattern.to_uppercase())
                || (!config_upper.contains(&enabled_pattern.to_uppercase())
                    && !config_upper.contains(&module_pattern.to_uppercase()))
            {
                findings.push(KernelMitigationAuditor::create_config_finding(
                    format!("{} — {}", display_name, remediation),
                    *severity,
                    file_path,
                    remediation,
                ));
            }
        }

        findings
    }

    fn create_config_finding(
        description: String,
        severity: Severity,
        file_path: &Path,
        remediation: &str,
    ) -> Finding {
        Finding {
            id: crate::new_finding_id(),
            severity,
            cwe: Some("CWE-693".to_string()),
            cve: None,
            description,
            file_path: Some(file_path.to_path_buf()),
            line_number: None,
            vulnerable_code_snippet: None,
            remediation: Some(remediation.to_string()),
            confidence: 0.9,
            discovery_method: DiscoveryMethod::StaticPatternMatching,
            exploit_code: None,
            exploit_type: None,
            chained_findings: vec![],
            poc_validated: false,
            status: FindingStatus::Open,
            cvss_score: Some(match severity {
                Severity::Critical => 9.0,
                Severity::High => 7.5,
                Severity::Medium => 5.0,
                Severity::Low => 3.0,
                Severity::Info => 1.0,
            }),
            severity_confidence: 0.9,
            discovered_at: Utc::now(),
            disclosed: false,
            disclosure_hash: None,
        }
    }
}
