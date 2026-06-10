#[derive(Default)]
pub struct JavaScriptAnalyzer;

impl super::LanguageAnalyzer for JavaScriptAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::JavaScript
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["js", "mjs"]
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

            // XSS via innerHTML
            if trimmed.contains("innerHTML") || trimmed.contains("outerHTML") {
                findings.push(self.create_finding(
                    "Potential XSS via innerHTML",
                    "CWE-79",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use textContent or sanitize input",
                ));
            }

            // Eval usage
            if trimmed.contains("eval(") {
                findings.push(self.create_finding(
                    "Unsafe eval() usage",
                    "CWE-95",
                    crate::Severity::Critical,
                    i,
                    line,
                    file_path,
                    "Avoid dynamic code execution",
                ));
            }

            // SQL injection (simplified)
            if (trimmed.contains("executeQuery") || trimmed.contains("execute("))
                && (trimmed.contains("+") || trimmed.contains("${"))
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
        }

        findings
    }
}

#[derive(Default)]
pub struct TypeScriptAnalyzer;

impl super::LanguageAnalyzer for TypeScriptAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::TypeScript
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["ts", "tsx"]
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

            // Using 'any' type (TypeScript)
            if trimmed.contains(": any") || trimmed.contains("<any>") {
                findings.push(self.create_finding(
                    "Usage of 'any' type defeats type safety",
                    "CWE-20",
                    crate::Severity::Low,
                    i,
                    line,
                    file_path,
                    "Use specific types instead of any",
                ));
            }

            // Unsafe type assertions
            if trimmed.contains("!") && trimmed.contains(":") && trimmed.contains("as ") {
                findings.push(self.create_finding(
                    "Non-null assertion or unsafe cast",
                    "CWE-20",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Add proper null checks",
                ));
            }

            // Same JS patterns
            if trimmed.contains("innerHTML") || trimmed.contains("eval(") {
                findings.push(self.create_finding(
                    "XSS or eval risk in TypeScript",
                    "CWE-79",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use safe alternatives",
                ));
            }
        }

        findings
    }
}

#[derive(Default)]
pub struct WebAppAnalyzer;

impl super::LanguageAnalyzer for WebAppAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::Other
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["html", "htm", "php", "jsp"]
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

            // XSS in HTML
            if trimmed.contains("<script>") && !file_path.to_string_lossy().contains(".js") {
                findings.push(self.create_finding(
                    "Inline script in HTML",
                    "CWE-79",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Use external scripts or CSP",
                ));
            }
        }

        findings
    }
}

impl JavaScriptAnalyzer {
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

impl TypeScriptAnalyzer {
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

impl WebAppAnalyzer {
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
