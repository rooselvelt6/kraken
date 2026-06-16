#[derive(Default)]
pub struct LinuxKernelAnalyzer;

impl super::LanguageAnalyzer for LinuxKernelAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::LinuxKernel
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["c", "h"]
    }

    fn analyze(
        &self,
        content: &str,
        file_path: &std::path::Path,
        _config: &crate::ScanConfig,
    ) -> Vec<crate::Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("strcpy")
                || trimmed.contains("strcat")
                || trimmed.contains("memcpy") && !trimmed.contains("n")
            {
                findings.push(self.create_finding(
                    "Buffer overflow risk in kernel code",
                    "CWE-120",
                    crate::Severity::Critical,
                    i,
                    line,
                    file_path,
                    "Use strncpy/strncat or check bounds",
                ));
            }

            if (trimmed.contains("*") || trimmed.contains("->"))
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("/*")
                && !trimmed.contains("if ")
                && !trimmed.contains("assert")
                && trimmed.contains("= *")
            {
                findings.push(self.create_finding(
                    "Potential NULL pointer dereference in kernel",
                    "CWE-476",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Add NULL check before dereferencing pointer",
                ));
            }

            if (trimmed.contains("mutex_lock") || trimmed.contains("spin_lock"))
                && !trimmed.starts_with("//")
            {
                findings.push(self.create_finding(
                    "Lock acquired — verify unlock paths for potential deadlock",
                    "CWE-667",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Ensure every lock has a corresponding unlock on all exit paths",
                ));
            }

            if trimmed.contains("kfree") || trimmed.contains("kfree_sensitive")
            {
                let next_lines: Vec<&str> = lines.iter().skip(i + 1).take(10).copied().collect();
                let has_access = next_lines.iter().any(|l| {
                    let t = l.trim();
                    (t.contains("->") || t.contains("*")) && !t.starts_with("//")
                });
                if has_access && next_lines.iter().any(|l| l.trim().contains("->"))
                {
                    findings.push(self.create_finding(
                        "Potential use-after-free: kfree followed by pointer access",
                        "CWE-416",
                        crate::Severity::Critical,
                        i,
                        line,
                        file_path,
                        "Set pointer to NULL after kfree and check before use",
                    ));
                }
            }
        }

        findings
    }
}

#[derive(Default)]
pub struct OpenBSDAnalyzer;

impl super::LanguageAnalyzer for OpenBSDAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::OpenBSD
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["c", "h"]
    }

    fn analyze(
        &self,
        content: &str,
        file_path: &std::path::Path,
        _config: &crate::ScanConfig,
    ) -> Vec<crate::Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // TCP SACK related issues (historical OpenBSD vulns)
            if trimmed.contains("tcp_sack") || trimmed.contains("TCP_SACK") {
                findings.push(self.create_finding(
                    "TCP SACK processing - verify bounds checking",
                    "CWE-125",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Check input validation in SACK processing",
                ));
            }

            // Buffer overflows
            if trimmed.contains("strcpy") || trimmed.contains("strcat") {
                findings.push(self.create_finding(
                    "Buffer overflow risk",
                    "CWE-120",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use safe string functions",
                ));
            }

            // Privilege separation issues
            if trimmed.contains("setuid") || trimmed.contains("setgid") {
                findings.push(self.create_finding(
                    "Privilege change - verify context",
                    "CWE-250",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Ensure proper privilege drop",
                ));
            }
        }

        findings
    }
}

#[derive(Default)]
pub struct FreeBSDAnalyzer;

impl super::LanguageAnalyzer for FreeBSDAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::FreeBSD
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["c", "h"]
    }

    fn analyze(
        &self,
        content: &str,
        file_path: &std::path::Path,
        _config: &crate::ScanConfig,
    ) -> Vec<crate::Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // NFS related vulnerabilities (historical)
            if trimmed.contains("nfs") && (trimmed.contains("malloc") || trimmed.contains("copy")) {
                findings.push(self.create_finding(
                    "NFS memory operation - verify bounds",
                    "CWE-125",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Check buffer sizes in NFS operations",
                ));
            }

            // RCE patterns (simplified)
            if trimmed.contains("system(") || trimmed.contains("exec(") {
                findings.push(self.create_finding(
                    "Command execution in kernel",
                    "CWE-78",
                    crate::Severity::Critical,
                    i,
                    line,
                    file_path,
                    "Avoid command execution in kernel context",
                ));
            }

            // Use after free
            if trimmed.contains("free(")
                && content
                    .lines()
                    .skip(i + 1)
                    .take(20)
                    .any(|l| l.contains("->") || l.contains("*"))
            {
                // Simplified check
            }
        }

        findings
    }
}

impl LinuxKernelAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        &self,
        desc: &str,
        cwe: &str,
        severity: crate::Severity,
        line_num: usize,
        line: &str,
        path: &std::path::Path,
        remediation: &str,
    ) -> crate::Finding {
        crate::Finding {
            id: crate::new_finding_id(),
            severity,
            cwe: Some(cwe.to_string()),
            cve: None,
            description: desc.to_string(),
            file_path: Some(path.to_path_buf()),
            line_number: Some(line_num as u32 + 1),
            vulnerable_code_snippet: Some(line.trim().to_string()),
            remediation: Some(remediation.to_string()),
            confidence: 0.7,
            discovery_method: crate::DiscoveryMethod::StaticPatternMatching,
            ..Default::default()
        }
    }
}

impl OpenBSDAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        &self,
        desc: &str,
        cwe: &str,
        severity: crate::Severity,
        line_num: usize,
        line: &str,
        path: &std::path::Path,
        remediation: &str,
    ) -> crate::Finding {
        crate::Finding {
            id: crate::new_finding_id(),
            severity,
            cwe: Some(cwe.to_string()),
            cve: None,
            description: desc.to_string(),
            file_path: Some(path.to_path_buf()),
            line_number: Some(line_num as u32 + 1),
            vulnerable_code_snippet: Some(line.trim().to_string()),
            remediation: Some(remediation.to_string()),
            confidence: 0.7,
            discovery_method: crate::DiscoveryMethod::StaticPatternMatching,
            ..Default::default()
        }
    }
}

impl FreeBSDAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        &self,
        desc: &str,
        cwe: &str,
        severity: crate::Severity,
        line_num: usize,
        line: &str,
        path: &std::path::Path,
        remediation: &str,
    ) -> crate::Finding {
        crate::Finding {
            id: crate::new_finding_id(),
            severity,
            cwe: Some(cwe.to_string()),
            cve: None,
            description: desc.to_string(),
            file_path: Some(path.to_path_buf()),
            line_number: Some(line_num as u32 + 1),
            vulnerable_code_snippet: Some(line.trim().to_string()),
            remediation: Some(remediation.to_string()),
            confidence: 0.7,
            discovery_method: crate::DiscoveryMethod::StaticPatternMatching,
            ..Default::default()
        }
    }
}
