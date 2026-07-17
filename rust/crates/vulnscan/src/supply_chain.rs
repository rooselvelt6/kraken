use crate::{DiscoveryMethod, Finding, FindingStatus, Language, Severity};
use chrono::Utc;
use std::path::Path;

pub struct SupplyChainAnalyzer;

impl SupplyChainAnalyzer {
    pub fn analyze(content: &str, file_path: &Path, language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();
        match language {
            Language::Rust => findings.extend(Self::check_cargo_toml(content, file_path)),
            Language::JavaScript | Language::TypeScript => {
                findings.extend(Self::check_package_json(content, file_path))
            }
            Language::Python => findings.extend(Self::check_requirements(content, file_path)),
            _ => {}
        }
        findings
    }

    fn check_cargo_toml(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if !file_path.ends_with("Cargo.toml") {
            return findings;
        }
        if content.contains("\"*\"") || content.contains(" = \"*\"") {
            findings.push(Finding {
                id: crate::new_finding_id(),
                severity: Severity::High,
                cwe: Some("CWE-1104".to_string()),
                cve: None,
                description: "Wildcard dependency version detected — supply chain risk".to_string(),
                file_path: Some(file_path.to_path_buf()),
                line_number: None,
                vulnerable_code_snippet: None,
                remediation: Some(
                    "Pin dependency versions instead of using wildcard '*'".to_string(),
                ),
                confidence: 0.9,
                discovery_method: DiscoveryMethod::SupplyChain,
                exploit_code: None,
                exploit_type: None,
                chained_findings: vec![],
                poc_validated: false,
                status: FindingStatus::Open,
                cvss_score: Some(7.0),
                severity_confidence: 0.9,
                discovered_at: Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            });
        }
        findings
    }

    fn check_package_json(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if content.contains("\"*\"") || content.contains("\">=\"") {
            findings.push(Finding {
                id: crate::new_finding_id(),
                severity: Severity::High,
                cwe: Some("CWE-1104".to_string()),
                cve: None,
                description: "Loose dependency version constraint in package.json".to_string(),
                file_path: Some(file_path.to_path_buf()),
                line_number: None,
                vulnerable_code_snippet: None,
                remediation: Some("Pin exact versions for production dependencies".to_string()),
                confidence: 0.7,
                discovery_method: DiscoveryMethod::SupplyChain,
                exploit_code: None,
                exploit_type: None,
                chained_findings: vec![],
                poc_validated: false,
                status: FindingStatus::Open,
                cvss_score: Some(6.0),
                severity_confidence: 0.7,
                discovered_at: Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            });
        }
        findings
    }

    fn check_requirements(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !trimmed.contains("==") && !trimmed.contains(">=") && !trimmed.contains("<=") {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Medium,
                    cwe: Some("CWE-1104".to_string()),
                    cve: None,
                    description: format!("Unpinned Python dependency: {}", trimmed),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: Some((i + 1) as u32),
                    vulnerable_code_snippet: Some(trimmed.to_string()),
                    remediation: Some("Pin dependency version with == or ~=".to_string()),
                    confidence: 0.7,
                    discovery_method: DiscoveryMethod::SupplyChain,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(5.0),
                    severity_confidence: 0.7,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                });
            }
        }
        findings
    }
}
