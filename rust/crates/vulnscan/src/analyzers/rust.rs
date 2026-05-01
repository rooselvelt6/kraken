use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use regex::Regex;
use std::path::Path;

pub struct RustAnalyzer {
    unsafe_re: Regex,
}

impl Default for RustAnalyzer {
    fn default() -> Self {
        Self {
            unsafe_re: Regex::new(r"unsafe").unwrap(),
        }
    }
}

impl super::LanguageAnalyzer for RustAnalyzer {
    fn language(&self) -> Language {
        Language::Rust
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["rs"]
    }
    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if self.unsafe_re.is_match(line) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Medium,
                    cwe: Some("CWE-20".to_string()),
                    cve: None,
                    description: "Unsafe block".to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: Some(i as u32 + 1),
                    vulnerable_code_snippet: Some(line.trim().to_string()),
                    remediation: Some("Review unsafe".to_string()),
                    confidence: 0.9,
                    discovery_method: DiscoveryMethod::StaticPatternMatching,
                });
            }
        }
        findings
    }
}
