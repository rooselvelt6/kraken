use crate::{DiscoveryMethod, Finding, FindingStatus, Severity};
use chrono::Utc;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

// ── Canonical secret patterns (shared across detect + redact) ──

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("api_key", r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{8,}"#),
    ("auth_token", r#"(?i)(?:auth[_-]?token|bearer[_-]?token|access[_-]?token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-.]{8,}"#),
    ("jwt", r#"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"#),
    ("github_token", r#"(?i)gh[psu]_[a-zA-Z0-9_\-]{16,}"#),
    ("aws_key", r#"AKIA[0-9A-Z]{16}"#),
    ("aws_secret", r#"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*['"]?[a-zA-Z0-9+/=]{40}"#),
    ("ssh_private", r#"-----BEGIN\s+\w+(?:\s+\w+)?\s+KEY-----"#),
    ("slack_token", r#"xox[baprs]-[a-zA-Z0-9\-]{10,}"#),
    ("discord_token", r#"[a-zA-Z0-9_\-]{24}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}"#),
    ("generic_secret", r#"(?i)(?:secret|password|passwd|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-!@#$%^&*()+]{8,}"#),
    ("stripe_key", r#"(?i)(?:sk_live|pk_live|sk_test|pk_test)_[a-zA-Z0-9]{24,}"#),
    ("google_api", r#"(?i)AIza[0-9A-Za-z\-_]{35}"#),
    ("firebase", r#"(?i)AAAA[A-Za-z0-9\-_]{37,}"#),
    ("heroku_api", r#"(?i)[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"#),
    ("pem_private", r#"-----BEGIN\s+PRIVATE\s+KEY-----"#),
    ("pgp_private", r#"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"#),
    ("ssh_private_key_file", r#"(?i)-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----"#),
];

static COMPILED_PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

#[derive(Debug, Clone)]
struct CompiledPattern {
    name: &'static str,
    regex: Regex,
}

fn compiled_patterns() -> &'static Vec<CompiledPattern> {
    COMPILED_PATTERNS.get_or_init(|| {
        SECRET_PATTERNS
            .iter()
            .filter_map(|(name, pattern)| {
                Regex::new(pattern).ok().map(|regex| CompiledPattern { name, regex })
            })
            .collect()
    })
}

// ── SecretsRedactor (formerly in security crate) ──

#[derive(Debug, Clone)]
pub struct SecretsRedactor {
    patterns: Vec<CompiledPattern>,
    redact_with: String,
}

impl SecretsRedactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_custom(patterns: Vec<(&'static str, &str)>, redact_with: &str) -> Self {
        let compiled = patterns
            .into_iter()
            .filter_map(|(name, pattern)| {
                Regex::new(pattern).ok().map(|regex| CompiledPattern { name, regex })
            })
            .collect();
        Self {
            patterns: compiled,
            redact_with: redact_with.to_string(),
        }
    }

    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();
        for cp in &self.patterns {
            result = cp.regex.replace_all(&result, &self.redact_with).to_string();
        }
        result
    }

    pub fn contains_secret(&self, input: &str) -> bool {
        self.patterns.iter().any(|cp| cp.regex.is_match(input))
    }

    pub fn redact_sensitive_value(key: &str, value: &str) -> String {
        let sensitive_keys = [
            "api_key", "apikey", "api-key",
            "secret", "secret_key", "secret-key",
            "password", "passwd", "pass",
            "token", "auth_token", "bearer",
            "access_token", "refresh_token",
            "private_key", "private-key", "privkey",
            "ssh_key", "ssh-key",
            "db_password", "db-password",
            "jwt", "session_key",
        ];
        let lower = key.to_lowercase();
        if sensitive_keys.iter().any(|k| lower.contains(k)) && !value.is_empty() {
            if value.len() <= 4 {
                return "***".to_string();
            }
            let prefix = &value[..value.len().min(4)];
            format!("{prefix}...")
        } else {
            value.to_string()
        }
    }
}

impl Default for SecretsRedactor {
    fn default() -> Self {
        Self::with_custom(SECRET_PATTERNS.to_vec(), "[REDACTED]")
    }
}

static GLOBAL_REDACTOR: OnceLock<SecretsRedactor> = OnceLock::new();

pub fn global_redactor() -> &'static SecretsRedactor {
    GLOBAL_REDACTOR.get_or_init(SecretsRedactor::default)
}

pub fn redact_secrets(input: &str) -> String {
    global_redactor().redact(input)
}

pub fn contains_secrets(input: &str) -> bool {
    global_redactor().contains_secret(input)
}

// ── SecretsDetector (enhanced from vulnscan) ──

pub struct SecretsDetector;

impl SecretsDetector {
    pub fn scan(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(Self::scan_patterns(content, file_path));
        findings.extend(Self::scan_entropy(content, file_path));
        findings
    }

    pub fn scan_binary(data: &[u8], file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Ok(extracted) = String::from_utf8(
            data.iter().copied().filter(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()).collect(),
        ) {
            findings.extend(Self::scan_patterns(&extracted, file_path));
            findings.extend(Self::scan_entropy(&extracted, file_path));
        }
        let hex = data.iter().map(|b| format!("{:02x}", b).chars().next().unwrap_or('0')).collect::<String>();
        findings.extend(Self::scan_patterns(&hex, file_path));
        findings
    }

    pub fn scan_git_log(git_output: &str, repo_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut current_commit = String::new();
        let mut current_file = String::new();
        let mut added_lines = Vec::new();

        for line in git_output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("commit ") {
                if !current_commit.is_empty() && !added_lines.is_empty() {
                    let content = added_lines.join("\n");
                    let mut commit_findings = Self::scan_patterns(&content, repo_path);
                    for f in &mut commit_findings {
                        f.description = format!("{} (found in git history, may be removed)", f.description);
                        f.remediation = Some(format!(
                            "{}. Rotate the exposed secret and use `git filter-branch` or `bfg` to remove it from history.",
                            f.remediation.as_deref().unwrap_or("Remove the secret from the codebase")
                        ));
                    }
                    findings.extend(commit_findings);
                }
                current_commit = trimmed.replacen("commit ", "", 1);
                current_file.clear();
                added_lines.clear();
                continue;
            }

            if trimmed.starts_with("--- a/") || trimmed.starts_with("+++ b/") {
                current_file = trimmed.trim_start_matches("--- a/").trim_start_matches("+++ b/").to_string();
                continue;
            }

            if trimmed.starts_with("+") && !trimmed.starts_with("+++") {
                added_lines.push(&line[1..]);
            }

            if trimmed.starts_with("-") && !trimmed.starts_with("---") {
                added_lines.push(&line[1..]);
            }
        }

        if !current_commit.is_empty() && !added_lines.is_empty() {
            let content = added_lines.join("\n");
            let mut commit_findings = Self::scan_patterns(&content, repo_path);
            for f in &mut commit_findings {
                f.description = format!("{} (found in git history)", f.description);
                f.remediation = Some(format!(
                    "{}. Rotate the exposed secret and use git filter-branch or bfg to remove it from history.",
                    f.remediation.as_deref().unwrap_or("Remove the secret from the codebase")
                ));
            }
            findings.extend(commit_findings);
        }

        findings
    }

    fn scan_patterns(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = compiled_patterns();

        for cp in patterns {
            for (i, line) in content.lines().enumerate() {
                if cp.regex.is_match(line) {
                    let cleaned = mask_secret(line);
                    let severity = match cp.name {
                        "ssh_private" | "pem_private" | "pgp_private" | "ssh_private_key_file" => Severity::Critical,
                        "aws_key" | "aws_secret" | "github_token" | "stripe_key" => Severity::Critical,
                        _ => Severity::High,
                    };
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity,
                        cwe: Some("CWE-798".to_string()),
                        cve: None,
                        description: format!("Hardcoded secret detected: {}", cp.name),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(cleaned),
                        remediation: Some(
                            "Move secrets to environment variables or a secrets manager"
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
                    });
                }
            }
        }
        findings
    }

    fn scan_entropy(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.len() < 16 || trimmed.len() > 256 {
                continue;
            }

            let entropy = shannon_entropy(trimmed);
            if entropy > 4.5 {
                let digit_ratio = trimmed.chars().filter(|c| c.is_ascii_digit()).count() as f64 / trimmed.len() as f64;

                let upper_ratio = trimmed.chars().filter(|c| c.is_ascii_uppercase()).count() as f64 / trimmed.len() as f64;

                let special_ratio = trimmed
                    .chars()
                    .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
                    .count() as f64
                    / trimmed.len() as f64;

                if digit_ratio > 0.15 && upper_ratio > 0.15 && special_ratio > 0.05 && entropy > 5.0 {
                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity: Severity::Medium,
                        cwe: Some("CWE-798".to_string()),
                        cve: None,
                        description: "High-entropy string detected (possible secret)".to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: Some((i + 1) as u32),
                        vulnerable_code_snippet: Some(mask_secret(trimmed)),
                        remediation: Some(
                            "If this is a secret, move it to environment variables or a secrets manager. \
                             If it's a false positive, add it to an allowlist."
                                .to_string(),
                        ),
                        confidence: 0.6,
                        discovery_method: DiscoveryMethod::SecretsDetection,
                        exploit_code: None,
                        exploit_type: None,
                        chained_findings: vec![],
                        poc_validated: false,
                        status: FindingStatus::Open,
                        cvss_score: Some(6.0),
                        severity_confidence: 0.6,
                        discovered_at: Utc::now(),
                        disclosed: false,
                        disclosure_hash: None,
                    });
                }
            }
        }
        findings
    }
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq = [0usize; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    -freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

fn mask_secret(line: &str) -> String {
    if line.len() > 30 {
        format!("{}...{}", &line[..15], &line[line.len() - 5..])
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── Redactor tests ──

    #[test]
    fn redacts_api_key() {
        let redacted = SecretsRedactor::default()
            .redact("my api_key=sk-test-12345abcdef is secret");
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("sk-test"));
    }

    #[test]
    fn redacts_jwt() {
        let redacted = SecretsRedactor::default()
            .redact("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j6TQvPXKtj_bSqtZISdPwQoA");
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_github_token() {
        let redacted = SecretsRedactor::default()
            .redact("ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_ssh_key() {
        let redacted = SecretsRedactor::default()
            .redact("-----BEGIN RSA PRIVATE KEY-----\nFAKE_DATA_FOR_UNIT_TEST...");
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_stripe_key() {
        let stripe_prefix = "sk_";
        let stripe_suffix = "live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let test_input = format!("{}{}", stripe_prefix, stripe_suffix);
        let redacted = SecretsRedactor::default()
            .redact(&test_input);
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn sensitive_value_truncation() {
        let result = SecretsRedactor::redact_sensitive_value("api_key", "sk-test-12345");
        assert!(result.starts_with("sk-t"));
        assert!(result.contains("..."));
    }

    #[test]
    fn non_sensitive_key_not_truncated() {
        let result = SecretsRedactor::redact_sensitive_value("username", "john_doe");
        assert_eq!(result, "john_doe");
    }

    #[test]
    fn contains_secret_detects() {
        assert!(SecretsRedactor::default().contains_secret("api_key=sk-test-12345abcdef"));
        assert!(!SecretsRedactor::default().contains_secret("hello world"));
    }

    #[test]
    fn global_redactor_works() {
        let redacted = redact_secrets("my token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j6TQvPXKtj_bSqtZISdPwQoA");
        assert!(redacted.contains("[REDACTED]"));
    }

    // ── Detector tests ──

    #[test]
    fn detect_api_key() {
        let findings = SecretsDetector::scan("api_key = \"sk-test-12345abcdef\"", &PathBuf::from("test.env"));
        assert!(findings.iter().any(|f| f.description.contains("api_key")));
    }

    #[test]
    fn detect_private_key() {
        let findings = SecretsDetector::scan(
            "-----BEGIN RSA PRIVATE KEY-----\nFAKE_DATA_FOR_UNIT_TEST...",
            &PathBuf::from("id_rsa"),
        );
        assert!(findings.iter().any(|f| f.description.contains("ssh_private")));
    }

    #[test]
    fn detect_github_token() {
        let findings = SecretsDetector::scan(
            "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            &PathBuf::from("test.env"),
        );
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_aws_key() {
        let findings = SecretsDetector::scan(
            "AKIAXXXXXXXXXXXXXXXX",
            &PathBuf::from("credentials"),
        );
        assert!(findings.iter().any(|f| f.description.contains("aws_key")));
    }

    #[test]
    fn detect_stripe_key() {
        let stripe_prefix = "sk_";
        let stripe_suffix = "live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let test_input = format!("{}{}", stripe_prefix, stripe_suffix);
        let findings = SecretsDetector::scan(
            &test_input,
            &PathBuf::from("config"),
        );
        assert!(findings.iter().any(|f| f.description.contains("stripe_key")));
    }

    #[test]
    fn detect_high_entropy() {
        let findings = SecretsDetector::scan(
            "aB3x9Kp2Lm7Qw1Rt5YzXcVbNmQwErTyUiOpAsDfGhJkLzXcVbNm1234567890!@#$%^&*()",
            &PathBuf::from("config"),
        );
        assert!(findings.iter().any(|f| f.description.contains("High-entropy")));
    }

    #[test]
    fn no_false_positive_low_entropy() {
        let findings = SecretsDetector::scan(
            "The quick brown fox jumps over the lazy dog",
            &PathBuf::from("readme.txt"),
        );
        assert!(!findings.iter().any(|f| f.description.contains("High-entropy")));
    }

    #[test]
    fn no_false_positive_quoted_entropy() {
        let findings = SecretsDetector::scan(
            "hello world this is a normal sentence with no secrets at all",
            &PathBuf::from("doc.txt"),
        );
        assert!(!findings.iter().any(|f| f.description.contains("High-entropy")));
    }

    #[test]
    fn scan_binary_extracts_strings() {
        let data = b"\x00\x01\x02api_key = \"sk-test-binary\"\x7f\xff";
        let findings = SecretsDetector::scan_binary(data, &PathBuf::from("binary.bin"));
        assert!(findings.iter().any(|f| f.description.contains("api_key")));
    }

    #[test]
    fn scan_git_log_detects_secrets() {
        let git_output = r#"commit abc123def456
Author: Test User
Date:   Mon Jan 1 00:00:00 2025

    Add config file

diff --git a/config.env b/config.env
new file mode 100644
--- /dev/null
+++ b/config.env
@@ -0,0 +1 @@
+API_KEY = "sk-test-12345abcdef"
"#;
        let findings = SecretsDetector::scan_git_log(git_output, &PathBuf::from("repo"));
        assert!(findings.iter().any(|f| f.description.contains("git history")));
    }

    #[test]
    fn shannon_entropy_calculation() {
        let e = shannon_entropy("aB3$x9Kp!2Lm#7Qw*1Rt&5Yz");
        assert!(e > 4.0, "entropy {} should be > 4.0", e);
        let e_low = shannon_entropy("aaaaaa");
        assert!(e_low < 2.0, "entropy {} should be < 2.0", e_low);
    }
}
