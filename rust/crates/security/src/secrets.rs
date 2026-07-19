//! Secret redaction utilities.
//!
//! The canonical secret detection and scanning module is in `vulnscan/src/secrets.rs`.
//! This crate re-exports the `SecretsRedactor` for use by other crates that need
//! redaction without the full `vulnscan` dependency.
//!
//! For unified detection (entropy, git history, binary scanning), use:
//!   vulnscan::secrets::SecretsDetector

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct SecretsRedactor {
    patterns: Vec<RedactPattern>,
    redact_with: String,
}

#[derive(Debug, Clone)]
struct RedactPattern {
    #[allow(dead_code)]
    name: &'static str,
    regex: Regex,
}

impl SecretsRedactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_custom(patterns: Vec<(&'static str, &str)>, redact_with: &str) -> Self {
        let compiled = patterns
            .into_iter()
            .filter_map(|(name, pattern)| {
                Regex::new(pattern).ok().map(|regex| RedactPattern { name, regex })
            })
            .collect();
        Self {
            patterns: compiled,
            redact_with: redact_with.to_string(),
        }
    }

    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();
        for pattern in &self.patterns {
            result = pattern
                .regex
                .replace_all(&result, &self.redact_with)
                .to_string();
        }
        result
    }

    pub fn contains_secret(&self, input: &str) -> bool {
        self.patterns.iter().any(|p| p.regex.is_match(input))
    }

    /// Redacts sensitive key values, showing only the first 4 characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use security::SecretsRedactor;
    ///
    /// let redacted = SecretsRedactor::redact_sensitive_value("api_key", "sk-test-12345");
    /// assert!(redacted.starts_with("sk-t"));
    /// assert!(redacted.ends_with("..."));
    ///
    /// let normal = SecretsRedactor::redact_sensitive_value("username", "alice");
    /// assert_eq!(normal, "alice");
    /// ```
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
        Self::with_custom(
            vec![
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
            ],
            "[REDACTED]",
        )
    }
}

static GLOBAL_REDACTOR: OnceLock<SecretsRedactor> = OnceLock::new();

pub fn global_redactor() -> &'static SecretsRedactor {
    GLOBAL_REDACTOR.get_or_init(SecretsRedactor::default)
}

/// Redacts secrets in a string using the global redactor.
///
/// # Examples
///
/// ```
/// use security::redact_secrets;
///
/// let safe = redact_secrets("my api_key=sk-test-12345abcdef is secret");
/// assert!(safe.contains("[REDACTED]"));
/// assert!(!safe.contains("sk-test-12345"));
/// ```
pub fn redact_secrets(input: &str) -> String {
    global_redactor().redact(input)
}

/// Checks if a string contains secret patterns.
///
/// # Examples
///
/// ```
/// use security::secrets::contains_secrets;
///
/// assert!(contains_secrets("api_key=sk-test-12345abcdef"));
/// assert!(!contains_secrets("hello world"));
/// ```
pub fn contains_secrets(input: &str) -> bool {
    global_redactor().contains_secret(input)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
