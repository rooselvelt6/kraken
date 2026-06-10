#[derive(Default)]
pub struct PythonAnalyzer;

impl super::LanguageAnalyzer for PythonAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::Python
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["py"]
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

            // SQL injection patterns
            if (trimmed.contains("execute(") || trimmed.contains("cursor.execute"))
                && (trimmed.contains("%s")
                    || trimmed.contains("format(")
                    || trimmed.contains("f\""))
            {
                findings.push(self.create_finding(
                    "SQL injection risk",
                    "CWE-89",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use parameterized queries",
                ));
            }

            // Command injection
            if trimmed.contains("os.system")
                || trimmed.contains("subprocess.call")
                || trimmed.contains("popen")
                || trimmed.contains("eval(")
            {
                findings.push(self.create_finding(
                    "Command injection or unsafe eval",
                    "CWE-78",
                    crate::Severity::Critical,
                    i,
                    line,
                    file_path,
                    "Avoid dynamic code execution",
                ));
            }

            // Pickle deserialization
            if trimmed.contains("pickle.load") || trimmed.contains("pickle.loads") {
                findings.push(self.create_finding(
                    "Unsafe deserialization with pickle",
                    "CWE-502",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use safe serialization formats",
                ));
            }

            // Hardcoded secrets
            if trimmed.to_lowercase().contains("password =")
                || trimmed.to_lowercase().contains("secret =")
                || trimmed.to_lowercase().contains("api_key =")
            {
                findings.push(self.create_finding(
                    "Potential hardcoded secret",
                    "CWE-798",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Use environment variables",
                ));
            }
        }

        findings
    }
}

impl PythonAnalyzer {
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
            ..Default::default()
        }
    }
}
