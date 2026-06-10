use crate::{DiscoveryMethod, Finding, FindingStatus, Language, Severity};
use chrono::Utc;
use regex::Regex;
use std::path::Path;

pub struct CryptoAnalyzer;

impl CryptoAnalyzer {
    pub fn analyze(content: &str, file_path: &Path, _language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(Self::check_tls_implementation(content, file_path));
        findings.extend(Self::check_aes_gcm(content, file_path));
        findings.extend(Self::check_weak_ciphers(content, file_path));
        findings.extend(Self::check_hardcoded_keys(content, file_path));
        findings.extend(Self::check_ssh_implementation(content, file_path));
        findings
    }

    fn check_tls_implementation(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if content.contains("TLSv1")
            && (content.contains("SSL_CTX_set_options") || content.contains("tls_config"))
        {
            for (i, line) in content.lines().enumerate() {
                if line.contains("TLSv1")
                    && (line.contains("SSLv3")
                        || line.contains("tls_v1_0")
                        || line.contains("tls_v1_1"))
                {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-327".to_string()),
                        cve: None,
                        description: "Use of broken or deprecated TLS protocol version".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Disable SSLv3, TLSv1.0, and TLSv1.1. Use TLSv1.2+".to_string(),
                        ),
                        confidence: 0.8,
                        discovery_method: DiscoveryMethod::CryptoAnalysis,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.5),
                        severity_confidence: 0.8,
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

    fn check_aes_gcm(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Some(pos) = content.find("AES") {
            if content[pos..].contains("ECB") {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Critical,
                    cwe: Some("CWE-327".to_string()),
                    cve: None,
                    description: "AES in ECB mode detected — not semantically secure".to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: Some(1),
                    vulnerable_code_snippet: Some(content[pos..pos + 50].to_string()),
                    remediation: Some("Use AES-GCM or AES-CCM instead of ECB mode".to_string()),
                    confidence: 0.9,
                    discovery_method: DiscoveryMethod::CryptoAnalysis,
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
        findings
    }

    fn check_weak_ciphers(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let weak = ["MD4", "MD5", "RC2", "RC4", "DES", "3DES", "SHA1"];
        for cipher in &weak {
            for (i, line) in content.lines().enumerate() {
                if line.contains(cipher) && !line.contains("//") && !line.contains("#") {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-327".to_string()),
                        cve: None,
                        description: format!(
                            "Use of broken/weak cryptographic algorithm: {}",
                            cipher
                        ),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(format!(
                            "Replace {} with a modern alternative (SHA-256, AES-GCM, ChaCha20)",
                            cipher
                        )),
                        confidence: 0.9,
                        discovery_method: DiscoveryMethod::CryptoAnalysis,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.5),
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

    fn check_hardcoded_keys(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let key_patterns = [Regex::new(
            r#"(?i)(private_key|secret_key|secret|password|passwd)\s*[:=]\s*['"][^'"]{8,}['"]"#,
        )
        .ok()];

        for pattern in key_patterns.iter().flatten() {
            for (i, line) in content.lines().enumerate() {
                if pattern.is_match(line) {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-798".to_string()),
                        cve: None,
                        description: "Hardcoded cryptographic key or secret detected".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Move secrets to environment variables or a secrets manager"
                                .to_string(),
                        ),
                        confidence: 0.7,
                        discovery_method: DiscoveryMethod::CryptoAnalysis,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.0),
                        severity_confidence: 0.7,
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

    fn check_ssh_implementation(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if content.contains("SSH") && content.contains("CBC") {
            findings.push(Finding {
                id: crate::new_finding_id(),
                severity: Severity::Medium,
                cwe: Some("CWE-327".to_string()),
                cve: None,
                description: "SSH CBC mode cipher detected — vulnerable to plaintext recovery"
                    .to_string(),
                file_path: Some(file_path.to_path_buf()),
                line_number: None,
                vulnerable_code_snippet: None,
                remediation: Some("Use CTR or ChaCha20-Poly1305 ciphers for SSH".to_string()),
                confidence: 0.7,
                discovery_method: DiscoveryMethod::CryptoAnalysis,
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
                ..Default::default()
            });
        }
        findings
    }
}
