#[derive(Default)]
pub struct RubyAnalyzer;

impl super::LanguageAnalyzer for RubyAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::Ruby
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["rb"]
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

            // Command injection
            if trimmed.contains("system(")
                || trimmed.contains("`")
                || trimmed.contains("exec(")
                || trimmed.contains("eval(")
            {
                findings.push(self.create_finding(
                    "Command injection or unsafe eval",
                    "CWE-78",
                    crate::Severity::Critical,
                    i,
                    line,
                    file_path,
                    "Avoid dynamic code/command execution",
                ));
            }

            // Marshal load (unsafe deserialization)
            if trimmed.contains("Marshal.load") || trimmed.contains("YAML.load") {
                findings.push(self.create_finding(
                    "Unsafe deserialization",
                    "CWE-502",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use safe deserialization methods",
                ));
            }

            // SQL injection in ActiveRecord
            if trimmed.contains("find_by_sql")
                || (trimmed.contains("execute(") && trimmed.contains("#{"))
            {
                findings.push(self.create_finding(
                    "Potential SQL injection",
                    "CWE-89",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use parameterized queries",
                ));
            }

            // XSS patterns
            if trimmed.contains("html_safe") || (trimmed.contains("raw ") && !trimmed.contains("#"))
            {
                findings.push(self.create_finding(
                    "Potential XSS vulnerability",
                    "CWE-79",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Escape output properly",
                ));
            }
        }

        findings
    }
}

impl RubyAnalyzer {
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
            confidence: 0.8,
            discovery_method: crate::DiscoveryMethod::StaticPatternMatching,
        }
    }
}
