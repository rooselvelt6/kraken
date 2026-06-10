use crate::{DiscoveryMethod, Finding, FindingStatus, Language, Severity};
use chrono::Utc;
use regex::Regex;
use std::path::Path;

pub struct WebAppScanner;

impl WebAppScanner {
    pub fn scan(content: &str, file_path: &Path, _language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(Self::check_sqli(content, file_path));
        findings.extend(Self::check_xss(content, file_path));
        findings.extend(Self::check_command_injection(content, file_path));
        findings.extend(Self::check_open_redirect(content, file_path));
        findings.extend(Self::check_path_traversal(content, file_path));
        findings.extend(Self::check_xxe(content, file_path));
        findings
    }

    fn check_sqli(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Raw SQL concatenation (classic SQLi)
        let sqli_fmt = Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE).*\$\{.*\{|\"\s*\+\s*[varuserinput]|format!\(.*SELECT|execute\(.*SELECT|query\(.*SELECT)"#).ok();
        if let Some(re) = sqli_fmt {
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::Critical,
                        cwe: Some("CWE-89".to_string()),
                        cve: None,
                        description:
                            "SQL Injection vulnerability — raw query concatenation detected"
                                .to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Use parameterized queries or prepared statements".to_string(),
                        ),
                        confidence: 0.8,
                        discovery_method: DiscoveryMethod::WebAppScan,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(9.5),
                        severity_confidence: 0.8,
                        discovered_at: Utc::now(),
                        disclosed: false,
                        disclosure_hash: None,
                        ..Default::default()
                    });
                }
            }
        }

        // String formatting in SQL
        for (i, line) in content.lines().enumerate() {
            if line.contains("format!") && (line.contains("SELECT") || line.contains("select")) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::Critical,
                    cwe: Some("CWE-89".to_string()),
                    cve: None,
                    description: "SQL Injection — format! macro used in SQL query".to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: Some((i + 1) as u32),
                    vulnerable_code_snippet: Some(line.to_string()),
                    remediation: Some(
                        "Use parameterized queries with sqlx::query() or diesel".to_string(),
                    ),
                    confidence: 0.7,
                    discovery_method: DiscoveryMethod::WebAppScan,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(9.0),
                    severity_confidence: 0.7,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                    ..Default::default()
                });
            }
        }
        findings
    }

    fn check_xss(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let xss_patterns = [
            "innerHTML",
            "outerHTML",
            "document.write",
            "dangerouslySetInnerHTML",
            "v-html",
            "ReactDOMServer",
            "eval(",
            "setTimeout(",
        ];

        for (i, line) in content.lines().enumerate() {
            for pattern in &xss_patterns {
                if line.contains(pattern) && !line.contains("//") {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-79".to_string()),
                        cve: None,
                        description: format!("Cross-Site Scripting (XSS) — {}", pattern),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Sanitize user input and use safe DOM APIs (textContent, innerText)"
                                .to_string(),
                        ),
                        confidence: 0.7,
                        discovery_method: DiscoveryMethod::WebAppScan,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(8.0),
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

    fn check_command_injection(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let cmd_patterns = [
            "std::process::Command",
            "system(",
            "exec(",
            "shell_exec",
            "popen",
            "subprocess.call",
            "subprocess.Popen",
            "os.system",
            "Runtime.getRuntime",
        ];

        for (i, line) in content.lines().enumerate() {
            for pattern in &cmd_patterns {
                if line.contains(pattern) {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-78".to_string()),
                        cve: None,
                        description: format!(
                            "Command Injection — {} with user input possible",
                            pattern
                        ),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Avoid shell commands with user input; use safe APIs".to_string(),
                        ),
                        confidence: 0.5,
                        discovery_method: DiscoveryMethod::WebAppScan,
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

    fn check_open_redirect(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let redirect_patterns = ["redirect(", "Redirect(", "Location:", "header(", "next:"];

        for (i, line) in content.lines().enumerate() {
            for pattern in &redirect_patterns {
                if line.contains(pattern)
                    && (line.contains("param")
                        || line.contains("query")
                        || line.contains("input")
                        || line.contains("url"))
                {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::Medium,
                        cwe: Some("CWE-601".to_string()),
                        cve: None,
                        description: "Open Redirect — user-controlled URL in redirect".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some("Validate and whitelist redirect URLs".to_string()),
                        confidence: 0.5,
                        discovery_method: DiscoveryMethod::WebAppScan,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(5.0),
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

    fn check_path_traversal(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let traversal_patterns = [
            "read_to_string",
            "read_file",
            "File::open",
            "fs::read",
            "open(",
            "fopen",
        ];

        for (i, line) in content.lines().enumerate() {
            for pattern in &traversal_patterns {
                if line.contains(pattern)
                    && (line.contains("..") || line.contains("../") || line.contains("..\\"))
                {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::High,
                        cwe: Some("CWE-22".to_string()),
                        cve: None,
                        description: "Path Traversal — user-controlled path with '../'".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(line.to_string()),
                        remediation: Some(
                            "Normalize and validate file paths; use a allowlist".to_string(),
                        ),
                        confidence: 0.8,
                        discovery_method: DiscoveryMethod::WebAppScan,
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

    fn check_xxe(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if content.contains("XMLReader")
            || content.contains("SimpleXMLElement")
            || content.contains("DocumentBuilder")
        {
            let has_xxe_protection = content.contains("LIBXML_NOENT")
                || content.contains("expandEntity")
                || content.contains("XXE");
            if !has_xxe_protection {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::High,
                    cwe: Some("CWE-611".to_string()),
                    cve: None,
                    description: "XML External Entity (XXE) Injection — XML parser without entity expansion protection".to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: None,
                    vulnerable_code_snippet: None,
                    remediation: Some("Disable XML entity expansion and external entity loading".to_string()),
                    confidence: 0.6,
                    discovery_method: DiscoveryMethod::WebAppScan,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: Some(8.0),
                    severity_confidence: 0.6,
                    discovered_at: Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                    ..Default::default()
                });
            }
        }
        findings
    }
}
