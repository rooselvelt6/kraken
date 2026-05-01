use crate::{DiscoveryMethod, Finding, Severity};
use regex::Regex;
use std::path::Path;

pub struct Cwe190Matcher {
    re: Regex,
}

impl Cwe190Matcher {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"malloc\s*\(.*\*.*\)|realloc\s*\(.*\*.*\)").unwrap(),
        }
    }
    pub fn matches(&self, content: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if self.re.is_match(line) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::High,
                    cwe: Some("CWE-190".to_string()),
                    cve: None,
                    description: "Potential integer overflow".to_string(),
                    file_path: Some(path.to_path_buf()),
                    line_number: Some(i as u32 + 1),
                    vulnerable_code_snippet: Some(line.trim().to_string()),
                    remediation: Some("Use checked arithmetic".to_string()),
                    confidence: 0.7,
                    discovery_method: DiscoveryMethod::StaticPatternMatching,
                });
            }
        }
        findings
    }
}

pub struct Cwe415Matcher {
    re: Regex,
}

impl Cwe415Matcher {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"free\s*\([^)]*\)\s*;.*free\s*\(").unwrap(),
        }
    }
    pub fn matches(&self, content: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if self.re.is_match(line) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Critical,
                    cwe: Some("CWE-415".to_string()),
                    cve: None,
                    description: "Potential double free".to_string(),
                    file_path: Some(path.to_path_buf()),
                    line_number: Some(i as u32 + 1),
                    vulnerable_code_snippet: Some(line.trim().to_string()),
                    remediation: Some("Set pointer to NULL after free".to_string()),
                    confidence: 0.8,
                    discovery_method: DiscoveryMethod::StaticPatternMatching,
                });
            }
        }
        findings
    }
}
