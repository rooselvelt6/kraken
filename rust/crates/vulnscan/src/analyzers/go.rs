use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use regex::Regex;
use std::path::Path;

pub struct GoAnalyzer {
    unsafe_re: Regex,
    sprintf_re: Regex,
    eval_re: Regex,
    sql_re: Regex,
}

impl Default for GoAnalyzer {
    fn default() -> Self {
        Self {
            unsafe_re: Regex::new(r"unsafe\.\w*").unwrap(),
            sprintf_re: Regex::new(r"fmt\.Sprintf\s*\(").unwrap(),
            eval_re: Regex::new(r"os\.Exec|\bexec\.Command").unwrap(),
            sql_re: Regex::new(r"(?i)\.(Exec|Query|QueryRow)\s*\(\s*`[^`]*\$").unwrap(),
        }
    }
}

impl super::LanguageAnalyzer for GoAnalyzer {
    fn language(&self) -> Language {
        Language::Go
    }
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["go"]
    }
    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let lineno = i as u32 + 1;
            if self.unsafe_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::High,
                    format!("Unsafe package usage: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Avoid unsafe package unless absolutely necessary".to_string()),
                    Some("CWE-676".to_string()),
                    0.8,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.sprintf_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Medium,
                    format!("Potential format string vulnerability: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Use constant format strings instead of user input".to_string()),
                    Some("CWE-134".to_string()),
                    0.7,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.eval_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::High,
                    format!("Command execution: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Validate and sanitize all command arguments".to_string()),
                    Some("CWE-78".to_string()),
                    0.8,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
            if self.sql_re.is_match(line) && !line.trim().starts_with("//") {
                findings.push(Finding::new(
                    Severity::Critical,
                    format!("Potential SQL injection: {}", line.trim()),
                    Some(file_path.to_path_buf()),
                    Some(lineno),
                    Some(line.trim().to_string()),
                    Some("Use parameterized queries instead of string interpolation".to_string()),
                    Some("CWE-89".to_string()),
                    0.9,
                    DiscoveryMethod::StaticPatternMatching,
                ));
            }
        }
        findings
    }
}
