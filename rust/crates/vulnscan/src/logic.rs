use crate::{DiscoveryMethod, Finding, FindingStatus, Language, Severity};
use chrono::Utc;
use std::path::Path;

pub struct LogicAnalyzer;

impl LogicAnalyzer {
    pub fn analyze(content: &str, file_path: &Path, _language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(Self::check_auth_bypass(content, file_path));
        findings.extend(Self::check_csrf(content, file_path));
        findings.extend(Self::check_idor(content, file_path));
        findings.extend(Self::check_ssrf(content, file_path));
        findings
    }

    fn check_auth_bypass(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let auth_patterns = [
            "is_admin",
            "isAdmin",
            "role == 'admin'",
            "role === 'admin'",
            "authenticated",
            "verify_token",
        ];

        for (i, line) in content.lines().enumerate() {
            for pattern in &auth_patterns {
                if line.contains(pattern) && line.contains("true") && !line.contains("false") {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-287".to_string()),
                        cve: None,
                        description: format!(
                            "Potential authentication bypass — '{}' hardcoded to true",
                            pattern
                        ),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Ensure auth checks use server-side validation, not client-side flags"
                                .to_string(),
                        ),
                        confidence: 0.5,
                        discovery_method: DiscoveryMethod::LogicAnalysis,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(8.5),
                        severity_confidence: 0.5,
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

    fn check_csrf(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if content.contains("POST") || content.contains("post") {
            let has_csrf =
                content.contains("csrf") || content.contains("CSRF") || content.contains("X-CSRF");
            let has_samesite = content.contains("SameSite") || content.contains("same_site");

            if !has_csrf && !has_samesite {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Medium,
                    cwe: Some("CWE-352".to_string()),
                    cve: None,
                    description:
                        "Potential CSRF vulnerability — POST endpoints without CSRF protection"
                            .to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: None,
                    vulnerable_code_snippet: None,
                    remediation: Some(
                        "Implement CSRF tokens or SameSite cookie attribute".to_string(),
                    ),
                    confidence: 0.4,
                    discovery_method: DiscoveryMethod::LogicAnalysis,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(6.0),
                    severity_confidence: 0.4,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                    ..Default::default()
                });
            }
        }
        findings
    }

    fn check_idor(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if content.contains("/api/") || content.contains("/v1/") || content.contains("/v2/") {
            let has_owner_check = content.contains("owner")
                || content.contains("user_id")
                || content.contains("authorize");

            if !has_owner_check {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::High,
                    cwe: Some("CWE-639".to_string()),
                    cve: None,
                    description: "Potential Insecure Direct Object Reference (IDOR) — API endpoints without ownership checks".to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: None,
                    vulnerable_code_snippet: None,
                    remediation: Some("Implement authorization checks to verify user ownership of requested resources".to_string()),
                    confidence: 0.3,
                    discovery_method: DiscoveryMethod::LogicAnalysis,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(7.5),
                    severity_confidence: 0.3,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                    ..Default::default()
                });
            }
        }
        findings
    }

    fn check_ssrf(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let url_fetch = [
            "fetch(", "request(", "urlopen(", "open(", "curl(", "reqwest", "http::",
        ];
        for (i, line) in content.lines().enumerate() {
            for pattern in &url_fetch {
                if line.contains(pattern)
                    && (line.contains("url") || line.contains("uri") || line.contains("params"))
                {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-918".to_string()),
                        cve: None,
                        description: "Potential Server-Side Request Forgery (SSRF) — user-controlled URL in server request".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some("Validate and whitelist allowed URLs/domains for server-side requests".to_string()),
                        confidence: 0.4,
                        discovery_method: DiscoveryMethod::LogicAnalysis,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(8.0),
                        severity_confidence: 0.4,
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
}
