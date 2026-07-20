pub mod fuzz;
pub mod kconfig;
pub mod patterns;
pub mod sanitizers;
pub mod version;

use crate::{DiscoveryMethod, Finding, FindingStatus, Severity};
use chrono::Utc;
use std::path::Path;

pub use kconfig::KernelConfig;
pub use version::KernelVersion;

pub struct KernelMitigationAuditor;

impl KernelMitigationAuditor {
    pub fn check_kconfig(content: &str, file_path: &Path) -> Vec<Finding> {
        let config = KernelConfig::parse(content, file_path);
        Self::check_config(&config, file_path)
    }

    pub fn check_config(config: &KernelConfig, file_path: &Path) -> Vec<Finding> {
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

        for (config_name, display_name, severity, remediation) in &checks {
            if config.is_disabled(config_name) {
                findings.push(Self::create_config_finding(
                    format!("{} — {}", display_name, remediation),
                    *severity,
                    file_path,
                    remediation,
                ));
            }
        }

        findings
    }

    pub fn audit_status(config: &KernelConfig) -> crate::mitigation::MitigationStatus {
        crate::mitigation::MitigationStatus {
            kernel_aslr: Some(config.is_enabled("CONFIG_RANDOMIZE_BASE")),
            kernel_smap: Some(config.is_enabled("CONFIG_X86_SMAP")),
            kernel_smep: Some(config.is_enabled("CONFIG_X86_SMEP")),
            kernel_kpti: Some(config.is_enabled("CONFIG_PAGE_TABLE_ISOLATION")),
            aslr: config.is_enabled("CONFIG_RANDOMIZE_BASE"),
            stack_canary: config.is_enabled("CONFIG_STACKPROTECTOR_STRONG")
                || config.is_enabled("CONFIG_STACKPROTECTOR"),
            relro: false,
            pie: false,
            cfi: config.is_enabled("CONFIG_CFI_CLANG"),
            fortify_source: config.is_enabled("CONFIG_FORTIFY_SOURCE"),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_check_kconfig_all_disabled() {
        let content = "# CONFIG_RANDOMIZE_BASE is not set\n# CONFIG_X86_SMAP is not set\n# CONFIG_X86_SMEP is not set\n# CONFIG_PAGE_TABLE_ISOLATION is not set\n";
        let findings = KernelMitigationAuditor::check_kconfig(content, &PathBuf::from(".config"));
        assert!(findings.len() >= 4);
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        assert!(high >= 4, "KASLR/SMAP/SMEP/KPTI should all be High severity");
    }

    #[test]
    fn test_check_kconfig_all_enabled() {
        let content = "CONFIG_RANDOMIZE_BASE=y\nCONFIG_X86_SMAP=y\nCONFIG_X86_SMEP=y\nCONFIG_PAGE_TABLE_ISOLATION=y\nCONFIG_STACKPROTECTOR=y\nCONFIG_STACKPROTECTOR_STRONG=y\nCONFIG_FORTIFY_SOURCE=y\nCONFIG_HARDENED_USERCOPY=y\nCONFIG_BUG_ON_DATA_CORRUPTION=y\nCONFIG_SECURITY=y\nCONFIG_SECURITY_SELINUX=y\nCONFIG_SECURITY_APPARMOR=y\nCONFIG_KASAN=y\nCONFIG_KCSAN=y\nCONFIG_SECURITY_DMESG_RESTRICT=y\nCONFIG_CFI_CLANG=y\n";
        let findings = KernelMitigationAuditor::check_kconfig(content, &PathBuf::from(".config"));
        assert_eq!(findings.len(), 0, "All mitigations enabled should produce no findings");
    }

    #[test]
    fn test_check_config_with_struct() {
        let config = KernelConfig::parse("CONFIG_RANDOMIZE_BASE=y\nCONFIG_X86_SMEP=y\n", &PathBuf::from(".config"));
        let findings = KernelMitigationAuditor::check_config(&config, &PathBuf::from(".config"));
        assert!(findings.iter().any(|f| f.description.contains("SMAP")));
        assert!(!findings.iter().any(|f| f.description.contains("KASLR")));
    }

    #[test]
    fn test_audit_status_all_enabled() {
        let config = KernelConfig::parse("CONFIG_RANDOMIZE_BASE=y\nCONFIG_X86_SMAP=y\nCONFIG_X86_SMEP=y\nCONFIG_PAGE_TABLE_ISOLATION=y\nCONFIG_STACKPROTECTOR_STRONG=y\nCONFIG_FORTIFY_SOURCE=y\n", &PathBuf::from(".config"));
        let status = KernelMitigationAuditor::audit_status(&config);
        assert!(status.kernel_aslr.unwrap());
        assert!(status.kernel_smap.unwrap());
        assert!(status.kernel_smep.unwrap());
        assert!(status.kernel_kpti.unwrap());
        assert!(status.stack_canary);
        assert!(status.fortify_source);
    }

    #[test]
    fn test_audit_status_all_disabled() {
        let config = KernelConfig::new();
        let status = KernelMitigationAuditor::audit_status(&config);
        assert!(!status.kernel_aslr.unwrap());
        assert!(!status.kernel_smap.unwrap());
        assert!(!status.kernel_smep.unwrap());
        assert!(!status.kernel_kpti.unwrap());
        assert!(!status.stack_canary);
    }

    #[test]
    fn test_check_kconfig_finding_severity_distribution() {
        let content = "# CONFIG_RANDOMIZE_BASE is not set\n# CONFIG_KASAN is not set\n# CONFIG_STACKPROTECTOR is not set\n";
        let findings = KernelMitigationAuditor::check_kconfig(content, &PathBuf::from(".config"));
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        assert!(high >= 1, "KASLR should be High");
        assert!(low >= 1, "KASAN should be Low");
        assert!(medium >= 1, "Stack Protector should be Medium");
    }
}
