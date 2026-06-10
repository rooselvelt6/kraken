use crate::{DiscoveryMethod, Finding, FindingStatus, Language, Severity};
use chrono::Utc;
use regex::Regex;
use std::path::Path;

pub struct SecretsDetector;

impl SecretsDetector {
    pub fn scan(content: &str, file_path: &Path, _language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(Self::check_api_keys(content, file_path));
        findings.extend(Self::check_private_keys(content, file_path));
        findings.extend(Self::check_tokens(content, file_path));
        findings.extend(Self::check_aws_keys(content, file_path));
        findings
    }

    fn check_api_keys(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            Regex::new(r#"(?i)(api[_-]?key|apikey|api_secret|api_secret_key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]"#).ok(),
            Regex::new(r"(?i)(sk-[a-zA-Z0-9]{20,})").ok(),
            Regex::new(r"(?i)(pk-[a-zA-Z0-9]{20,})").ok(),
        ];

        for pattern in patterns.iter().flatten() {
            for (i, line) in content.lines().enumerate() {
                if pattern.is_match(line) {
                    let cleaned = Self::mask_secret(line);
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::Critical,
                        cwe: Some("CWE-798".to_string()),
                        cve: None,
                        description: "Hardcoded API key detected".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(cleaned),
                        remediation: Some(
                            "Move API keys to environment variables or a secrets manager"
                                .to_string(),
                        ),
                        confidence: 0.9,
                        discovery_method: DiscoveryMethod::SecretsDetection,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(9.0),
                        severity_confidence: 0.9,
                        discovered_at: Utc::now(),
                        disclosed: false,
                        disclosure_hash: None,
                        ..Default::default()
                    });
                }
            }
        }
        findings
    }

    fn check_private_keys(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let key_header = Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").ok();

        if let Some(re) = key_header {
            if re.is_match(content) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Critical,
                    cwe: Some("CWE-798".to_string()),
                    cve: None,
                    description: "Private key file detected in repository".to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: None,
                    vulnerable_code_snippet: None,
                    remediation: Some(
                        "Remove private keys from repository and use ssh-agent or secrets manager"
                            .to_string(),
                    ),
                    confidence: 1.0,
                    discovery_method: DiscoveryMethod::SecretsDetection,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(10.0),
                    severity_confidence: 1.0,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                    ..Default::default()
                });
            }
        }
        findings
    }

    fn check_tokens(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let token_patterns = [
            Regex::new(r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9_]{36,}").ok(),
            Regex::new(r"(?i)(xfbd|xfat|xox[bpsa]-)[a-zA-Z0-9\-]{24,}").ok(),
        ];

        for pattern in token_patterns.iter().flatten() {
            for (i, line) in content.lines().enumerate() {
                if pattern.is_match(line) {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::Critical,
                        cwe: Some("CWE-798".to_string()),
                        cve: None,
                        description: "Hardcoded access token detected (GitHub/Slack)".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.chars().take(40).collect()),
                        remediation: Some(
                            "Revoke the exposed token and use environment variables".to_string(),
                        ),
                        confidence: 0.95,
                        discovery_method: DiscoveryMethod::SecretsDetection,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(9.5),
                        severity_confidence: 0.95,
                        discovered_at: Utc::now(),
                        disclosed: false,
                        disclosure_hash: None,
                        ..Default::default()
                    });
                }
            }
        }
        findings
    }

    fn check_aws_keys(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let aws_key = Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").ok();

        if let Some(re) = aws_key {
            for (i, line) in content.lines().enumerate() {
                if let Some(m) = re.find(line) {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::Critical,
                        cwe: Some("CWE-798".to_string()),
                        cve: None,
                        description: "AWS Access Key ID detected".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(m.as_str().to_string()),
                        remediation: Some(
                            "Rotate the AWS key and remove it from the codebase".to_string(),
                        ),
                        confidence: 0.95,
                        discovery_method: DiscoveryMethod::SecretsDetection,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(9.5),
                        severity_confidence: 0.95,
                        discovered_at: Utc::now(),
                        disclosed: false,
                        disclosure_hash: None,
                        ..Default::default()
                    });
                }
            }
        }
        findings
    }

    fn mask_secret(line: &str) -> String {
        if line.len() > 30 {
            format!("{}...{}", &line[..15], &line[line.len() - 5..])
        } else {
            line.to_string()
        }
    }
}
