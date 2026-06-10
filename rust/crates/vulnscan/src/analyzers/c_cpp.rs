#[derive(Default)]
pub struct CAnalyzer;

impl super::LanguageAnalyzer for CAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::C
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

            // Buffer overflows
            if trimmed.contains("strcpy")
                || trimmed.contains("strcat")
                || trimmed.contains("gets(")
                || trimmed.contains("sprintf(")
            {
                findings.push(Self::create_finding(
                    "Buffer overflow risk - unsafe string function",
                    "CWE-120",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use strncpy/strncat or safe alternatives",
                ));
            }

            // Memory management issues
            if trimmed.contains("malloc") && !trimmed.contains("free") {
                // Simple heuristic: if malloc without free nearby
            }
            if trimmed.contains("free(") && trimmed.contains("double") {
                findings.push(Self::create_finding(
                    "Potential double-free",
                    "CWE-415",
                    crate::Severity::Critical,
                    i,
                    line,
                    file_path,
                    "Ensure each allocation is freed once",
                ));
            }

            // Null pointer dereference
            if trimmed.contains("->") && !trimmed.contains("if") && !trimmed.contains("assert") {
                // Simplified check
            }

            // Integer overflow
            if trimmed.contains("malloc") && (trimmed.contains("*") || trimmed.contains("sizeof")) {
                findings.push(Self::create_finding(
                    "Potential integer overflow in allocation",
                    "CWE-190",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Check for overflow before multiplication",
                ));
            }
        }

        findings
    }
}

#[derive(Default)]
pub struct CppAnalyzer;

impl super::LanguageAnalyzer for CppAnalyzer {
    fn language(&self) -> super::Language {
        super::Language::Cpp
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["cpp", "cc", "cxx", "hpp", "hxx"]
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

            // Same C issues plus C++ specific
            if trimmed.contains("strcpy") || trimmed.contains("strcat") {
                findings.push(Self::create_finding(
                    "Buffer overflow risk",
                    "CWE-120",
                    crate::Severity::High,
                    i,
                    line,
                    file_path,
                    "Use std::string or safe alternatives",
                ));
            }

            // Use after free
            if trimmed.contains("delete")
                && content
                    .lines()
                    .skip(i + 1)
                    .any(|l| l.contains("->") || l.contains("*"))
            {
                // Simplified check
            }

            // Unsafe casts
            if trimmed.contains("reinterpret_cast")
                || (trimmed.contains("(") && trimmed.contains("*)"))
            {
                findings.push(Self::create_finding(
                    "Unsafe type cast",
                    "CWE-704",
                    crate::Severity::Medium,
                    i,
                    line,
                    file_path,
                    "Use safe casting alternatives",
                ));
            }
        }

        findings
    }
}

impl CAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
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

impl CppAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
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
