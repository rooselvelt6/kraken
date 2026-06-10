use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use regex::Regex;
use std::path::Path;

pub struct SwiftAnalyzer {
    force_unwrap_re: Regex,
    nsdata_re: Regex,
    xss_re: Regex,
    sql_re: Regex,
    eval_re: Regex,
}

impl Default for SwiftAnalyzer {
    fn default() -> Self {
        Self {
            force_unwrap_re: Regex::new(r"\w+!\s*\.").unwrap(),
            nsdata_re: Regex::new(r"NSData\s*\(contentsOf|dataWithContentsOf").unwrap(),
            xss_re: Regex::new(r"(?i)UIWebView|WKWebView.*loadHTMLString").unwrap(),
            sql_re: Regex::new(r"(?i)executeStatements|executeUpdate\s*\(").unwrap(),
            eval_re: Regex::new(r"NSExpression|NSPredicate\s*\(format:").unwrap(),
        }
    }
}

impl super::LanguageAnalyzer for SwiftAnalyzer {
    fn language(&self) -> Language {
        Language::Swift
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["swift"]
    }
    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let lineno = i as u32 + 1;
            if self.force_unwrap_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Medium,
                    format!("Force unwrapping optional: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some(
                        "Use optional binding (if let/guard let) instead of force unwrap"
                            .to_string(),
                    ),
                    Some("CWE-476".to_string()),
                    0.7,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.nsdata_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::High,
                    format!("Synchronous network data load: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Use asynchronous URLSession instead of synchronous NSData".to_string()),
                    Some("CWE-918".to_string()),
                    0.7,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.xss_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::High,
                    format!("WebView XSS risk: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Sanitize HTML before loading into WebView; prefer WKWebView with JS disabled".to_string()),
                    Some("CWE-79".to_string()),
                    0.8,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.sql_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Critical,
                    format!("SQL injection risk: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Use parameterized queries with sqlite3_bind_*".to_string()),
                    Some("CWE-89".to_string()),
                    0.9,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.eval_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Critical,
                    format!("Expression evaluation injection: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some(
                        "Avoid NSExpression/NSPredicate with user-controlled format strings"
                            .to_string(),
                    ),
                    Some("CWE-94".to_string()),
                    0.9,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
        }
        findings
    }
}
