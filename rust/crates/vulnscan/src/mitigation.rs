use crate::{DiscoveryMethod, Finding, FindingStatus, Severity};
use chrono::Utc;
use std::path::Path;

pub struct MitigationChecker;

#[derive(Debug, Clone)]
pub struct MitigationStatus {
    pub aslr: bool,
    pub stack_canary: bool,
    pub relro: bool,
    pub pie: bool,
    pub cfi: bool,
    pub fortify_source: bool,
    pub kernel_aslr: Option<bool>,
    pub kernel_smap: Option<bool>,
    pub kernel_smep: Option<bool>,
    pub kernel_kpti: Option<bool>,
}

impl MitigationChecker {
    /// Checks a Cargo.toml for missing security-related configurations.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::mitigation::MitigationChecker;
    /// use std::path::Path;
    /// let findings = MitigationChecker::check_cargo_toml("[package]\nname = \"test\"\n", Path::new("Cargo.toml"));
    /// assert!(!findings.is_empty());
    /// ```
    pub fn check_cargo_toml(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if !content.contains("panic = \"abort\"") {
            findings.push(Finding::info(
                "Consider setting panic = 'abort' in Cargo.toml release profile",
                Some(file_path.to_path_buf()),
                None,
                crate::DiscoveryMethod::StaticPatternMatching,
            ));
        }
        findings
    }

    /// Checks a Makefile for missing security compiler flags.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::mitigation::MitigationChecker;
    /// use std::path::Path;
    /// let findings = MitigationChecker::check_makefile("CC=gcc\n", Path::new("Makefile"));
    /// assert!(findings.iter().any(|f| f.description.contains("stack-protector")));
    /// ```
    pub fn check_makefile(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let flags = [
            ("-fstack-protector-strong", "Stack canary"),
            ("-D_FORTIFY_SOURCE=2", "FORTIFY_SOURCE"),
            ("-pie", "Position Independent Executable"),
            ("-Wl,-z,relro", "RELRO"),
            ("-Wl,-z,now", "BIND_NOW"),
        ];

        for (flag, name) in &flags {
            if !content.contains(flag) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Medium,
                    cwe: Some("CWE-693".to_string()),
                    cve: None,
                    description: format!(
                        "Missing {} — consider adding {} to build flags",
                        name, flag
                    ),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: None,
                    vulnerable_code_snippet: None,
                    remediation: Some(format!("Add {} to compiler flags", flag)),
                    confidence: 0.8,
                    discovery_method: DiscoveryMethod::StaticPatternMatching,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(4.0),
                    severity_confidence: 0.8,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                });
            }
        }
        findings
    }

    pub fn check_kernel_config(content: &str, file_path: &Path) -> Vec<Finding> {
        crate::kernel::KernelMitigationAuditor::check_kconfig(content, file_path)
    }

    pub fn check_kernel_config_struct(config: &crate::kernel::KernelConfig, file_path: &Path) -> Vec<Finding> {
        crate::kernel::KernelMitigationAuditor::check_config(config, file_path)
    }

    pub fn audit_kernel_status(config: &crate::kernel::KernelConfig) -> MitigationStatus {
        crate::kernel::KernelMitigationAuditor::audit_status(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_check_cargo_toml_missing_panic_abort() {
        let findings = MitigationChecker::check_cargo_toml("[package]\nname = \"test\"\n", Path::new("Cargo.toml"));
        assert!(!findings.is_empty());
        assert!(findings[0].description.contains("panic"));
    }

    #[test]
    fn test_check_cargo_toml_with_panic_abort() {
        let findings = MitigationChecker::check_cargo_toml("[package]\nname = \"test\"\n[profile.release]\npanic = \"abort\"\n", Path::new("Cargo.toml"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_makefile_missing_flags() {
        let findings = MitigationChecker::check_makefile("CC=gcc\n", Path::new("Makefile"));
        assert!(findings.len() >= 4);
        assert!(findings.iter().any(|f| f.description.contains("stack-protector")));
        assert!(findings.iter().any(|f| f.description.contains("FORTIFY_SOURCE")));
    }

    #[test]
    fn test_check_makefile_all_flags_present() {
        let findings = MitigationChecker::check_makefile("CC=gcc\nCFLAGS=-fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie\nLDFLAGS=-Wl,-z,relro -Wl,-z,now\n", Path::new("Makefile"));
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_kernel_config_content() {
        let content = "# CONFIG_RANDOMIZE_BASE is not set\nCONFIG_X86_SMEP=y\n";
        let findings = MitigationChecker::check_kernel_config(content, &PathBuf::from(".config"));
        assert!(findings.iter().any(|f| f.description.contains("KASLR")));
        assert!(!findings.iter().any(|f| f.description.starts_with("SMEP (Supervisor")));
    }

    #[test]
    fn test_check_kernel_config_struct() {
        let config = crate::kernel::KernelConfig::parse("CONFIG_RANDOMIZE_BASE=y\n", &PathBuf::from(".config"));
        let findings = MitigationChecker::check_kernel_config_struct(&config, &PathBuf::from(".config"));
        assert!(!findings.iter().any(|f| f.description.contains("KASLR")));
        assert!(findings.iter().any(|f| f.description.contains("SMAP")));
    }

    #[test]
    fn test_audit_kernel_status() {
        let config = crate::kernel::KernelConfig::parse("CONFIG_RANDOMIZE_BASE=y\nCONFIG_X86_SMAP=y\n", &PathBuf::from(".config"));
        let status = MitigationChecker::audit_kernel_status(&config);
        assert!(status.kernel_aslr.unwrap());
        assert!(status.kernel_smap.unwrap());
        assert!(!status.kernel_smep.unwrap());
    }
}
