use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use regex::Regex;
use std::path::Path;

pub struct JavaAnalyzer {
    exec_re: Regex,
    reflect_re: Regex,
    deserialize_re: Regex,
    sql_re: Regex,
    xss_re: Regex,
}

impl Default for JavaAnalyzer {
    fn default() -> Self {
        Self {
            exec_re: Regex::new(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder").unwrap(),
            reflect_re: Regex::new(r"Class\.forName\s*\(|Method\.invoke").unwrap(),
            deserialize_re: Regex::new(r"ObjectInputStream|readObject\s*\(").unwrap(),
            sql_re: Regex::new(
                r#"(?i)\.(executeQuery|executeUpdate|prepareStatement)\s*\(\s*"[^"]*\+"#,
            )
            .unwrap(),
            xss_re: Regex::new(
                r"println\s*\(\s*request\.getParameter|write\s*\(\s*request\.getParameter",
            )
            .unwrap(),
        }
    }
}

impl super::LanguageAnalyzer for JavaAnalyzer {
    fn language(&self) -> Language {
        Language::Java
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["java"]
    }
    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let lineno = i as u32 + 1;
            if self.exec_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::High,
                    format!("Command injection risk: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Avoid Runtime.exec with user input; use ProcessBuilder with sanitized args".to_string()),
                    Some("CWE-78".to_string()),
                    0.8,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.reflect_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Medium,
                    format!("Reflection usage: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Restrict reflection targets with a whitelist".to_string()),
                    Some("CWE-470".to_string()),
                    0.6,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.deserialize_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Critical,
                    format!("Insecure deserialization: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Use a whitelist for deserialization classes; prefer JSON".to_string()),
                    Some("CWE-502".to_string()),
                    0.9,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.sql_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Critical,
                    format!("SQL injection: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Use parameterized queries (PreparedStatement)".to_string()),
                    Some("CWE-89".to_string()),
                    0.9,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.xss_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Medium,
                    format!("XSS via response output: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Sanitize/HtmlEncode user input before writing to response".to_string()),
                    Some("CWE-79".to_string()),
                    0.7,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
        }
        findings
    }
}
