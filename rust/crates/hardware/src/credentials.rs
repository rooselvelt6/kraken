use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPattern {
    pub name: String,
    pub pattern: String,
    pub category: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundCredential {
    pub pattern_name: String,
    pub file_path: String,
    pub line_number: usize,
    pub matched_text: String,
    pub context: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialScanResult {
    pub total_files_scanned: usize,
    pub total_credentials_found: usize,
    pub high_severity: usize,
    pub medium_severity: usize,
    pub low_severity: usize,
    pub credentials: Vec<FoundCredential>,
    pub patterns_used: usize,
}

pub struct CredentialScanner;

impl Default for CredentialScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialScanner {
    pub fn new() -> Self {
        CredentialScanner
    }

    pub fn default_patterns() -> Vec<CredentialPattern> {
        vec![
            CredentialPattern {
                name: "Hardcoded Password".to_string(),
                pattern: r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]+)"#.to_string(),
                category: "password".to_string(),
                severity: "HIGH".to_string(),
                description: "Hardcoded password found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Hardcoded API Key".to_string(),
                pattern: r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([^\s'"]+)"#.to_string(),
                category: "api_key".to_string(),
                severity: "HIGH".to_string(),
                description: "Hardcoded API key found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Hardcoded Secret".to_string(),
                pattern: r#"(?i)(secret|token|auth)\s*[=:]\s*['"]?([^\s'"]+)"#.to_string(),
                category: "secret".to_string(),
                severity: "HIGH".to_string(),
                description: "Hardcoded secret found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Default Credentials".to_string(),
                pattern: r#"(?i)(admin|root|user|guest)\s*:\s*(admin|root|password|1234|toor)"#.to_string(),
                category: "default_creds".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Default credentials found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Private Key".to_string(),
                pattern: r#"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"#.to_string(),
                category: "private_key".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Private key found in firmware".to_string(),
            },
            CredentialPattern {
                name: "AWS Access Key".to_string(),
                pattern: r#"AKIA[0-9A-Z]{16}"#.to_string(),
                category: "cloud_key".to_string(),
                severity: "CRITICAL".to_string(),
                description: "AWS access key found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Generic Credential".to_string(),
                pattern: r#"(?i)(credential|cred)\s*[=:]\s*['"]?([^\s'"]+)"#.to_string(),
                category: "credential".to_string(),
                severity: "MEDIUM".to_string(),
                description: "Generic credential found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Database Connection String".to_string(),
                pattern: r#"(?i)(mysql|postgres|mongodb|redis)://[^\s]+"#.to_string(),
                category: "connection_string".to_string(),
                severity: "HIGH".to_string(),
                description: "Database connection string found in firmware".to_string(),
            },
            CredentialPattern {
                name: "JWT Token".to_string(),
                pattern: r#"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"#.to_string(),
                category: "jwt".to_string(),
                severity: "HIGH".to_string(),
                description: "JWT token found in firmware".to_string(),
            },
            CredentialPattern {
                name: "Base64 Encoded Secret".to_string(),
                pattern: r#"(?i)(key|secret|token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}"#.to_string(),
                category: "encoded_secret".to_string(),
                severity: "MEDIUM".to_string(),
                description: "Possible base64 encoded secret found".to_string(),
            },
        ]
    }

    pub fn scan_data(data: &[u8], file_path: &str, patterns: &[CredentialPattern]) -> Vec<FoundCredential> {
        let mut credentials = Vec::new();
        let text = String::from_utf8_lossy(data);

        for (line_num, line) in text.lines().enumerate() {
            for pattern in patterns {
                if let Ok(re) = regex::Regex::new(&pattern.pattern) {
                    if let Some(captures) = re.captures(line) {
                        let matched = captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
                        let context_start = line_num.saturating_sub(1);
                        let context_end = (line_num + 1).min(text.lines().count() - 1);
                        let context: Vec<&str> = text.lines().skip(context_start).take(context_end - context_start + 1).collect();

                        credentials.push(FoundCredential {
                            pattern_name: pattern.name.clone(),
                            file_path: file_path.to_string(),
                            line_number: line_num + 1,
                            matched_text: matched,
                            context: context.join("\n"),
                            severity: pattern.severity.clone(),
                        });
                    }
                }
            }
        }

        credentials
    }

    pub fn scan_binary(data: &[u8], file_path: &str) -> Vec<FoundCredential> {
        let patterns = Self::default_patterns();
        let mut credentials = Vec::new();

        let chunk_size = 8192;
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let offset = i * chunk_size;
            let chunk_creds = Self::scan_data(chunk, file_path, &patterns);
            for mut cred in chunk_creds {
                cred.line_number += offset;
                credentials.push(cred);
            }
        }

        credentials
    }

    pub fn scan_files(files: &[(String, Vec<u8>)]) -> CredentialScanResult {
        let patterns = Self::default_patterns();
        let mut all_credentials = Vec::new();
        let mut files_scanned = 0;

        for (path, data) in files {
            files_scanned += 1;
            let creds = Self::scan_data(data, path, &patterns);
            all_credentials.extend(creds);
        }

        let high = all_credentials.iter().filter(|c| c.severity == "HIGH" || c.severity == "CRITICAL").count();
        let medium = all_credentials.iter().filter(|c| c.severity == "MEDIUM").count();
        let low = all_credentials.iter().filter(|c| c.severity == "LOW").count();

        CredentialScanResult {
            total_files_scanned: files_scanned,
            total_credentials_found: all_credentials.len(),
            high_severity: high,
            medium_severity: medium,
            low_severity: low,
            credentials: all_credentials,
            patterns_used: patterns.len(),
        }
    }

    pub fn summarize_results(result: &CredentialScanResult) -> String {
        if result.total_credentials_found == 0 {
            return "No hardcoded credentials found.".to_string();
        }

        let mut summary = format!(
            "Found {} credentials in {} files ({} high, {} medium, {} low severity)\n\n",
            result.total_credentials_found,
            result.total_files_scanned,
            result.high_severity,
            result.medium_severity,
            result.low_severity
        );

        for cred in &result.credentials {
            summary.push_str(&format!(
                "[{}] {}:{} - {} ({})\n",
                cred.severity, cred.file_path, cred.line_number, cred.pattern_name, cred.matched_text
            ));
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_patterns() {
        let patterns = CredentialScanner::default_patterns();
        assert!(patterns.len() >= 8);
    }

    #[test]
    fn test_scan_data_password() {
        let data = b"password = \"secret123\"";
        let patterns = CredentialScanner::default_patterns();
        let creds = CredentialScanner::scan_data(data, "test.txt", &patterns);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].severity, "HIGH");
    }

    #[test]
    fn test_scan_data_default_creds() {
        let data = b"admin:admin";
        let patterns = CredentialScanner::default_patterns();
        let creds = CredentialScanner::scan_data(data, "test.txt", &patterns);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].severity, "CRITICAL");
    }

    #[test]
    fn test_scan_data_private_key() {
        let data = b"-----BEGIN RSA PRIVATE KEY-----";
        let patterns = CredentialScanner::default_patterns();
        let creds = CredentialScanner::scan_data(data, "test.txt", &patterns);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].severity, "CRITICAL");
    }

    #[test]
    fn test_scan_data_aws_key() {
        let data = b"AKIAIOSFODNN7EXAMPLE";
        let patterns = CredentialScanner::default_patterns();
        let creds = CredentialScanner::scan_data(data, "test.txt", &patterns);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].severity, "CRITICAL");
    }

    #[test]
    fn test_scan_data_no_creds() {
        let data = b"no credentials here";
        let patterns = CredentialScanner::default_patterns();
        let creds = CredentialScanner::scan_data(data, "test.txt", &patterns);
        assert!(creds.is_empty());
    }

    #[test]
    fn test_scan_binary() {
        let data = b"password = \"test123\"\napi_key = \"abc123\"";
        let creds = CredentialScanner::scan_binary(data, "test.bin");
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_scan_files() {
        let files = vec![
            ("file1.txt".to_string(), b"password = \"test\"".to_vec()),
            ("file2.txt".to_string(), b"admin:admin".to_vec()),
        ];
        let result = CredentialScanner::scan_files(&files);
        assert_eq!(result.total_files_scanned, 2);
        assert!(result.total_credentials_found >= 2);
    }

    #[test]
    fn test_summarize_results_empty() {
        let result = CredentialScanResult {
            total_files_scanned: 10,
            total_credentials_found: 0,
            high_severity: 0,
            medium_severity: 0,
            low_severity: 0,
            credentials: vec![],
            patterns_used: 10,
        };
        let summary = CredentialScanner::summarize_results(&result);
        assert!(summary.contains("No hardcoded credentials"));
    }

    #[test]
    fn test_summarize_results_with_creds() {
        let result = CredentialScanResult {
            total_files_scanned: 1,
            total_credentials_found: 1,
            high_severity: 1,
            medium_severity: 0,
            low_severity: 0,
            credentials: vec![FoundCredential {
                pattern_name: "Hardcoded Password".to_string(),
                file_path: "test.txt".to_string(),
                line_number: 1,
                matched_text: "password = secret".to_string(),
                context: "password = secret".to_string(),
                severity: "HIGH".to_string(),
            }],
            patterns_used: 10,
        };
        let summary = CredentialScanner::summarize_results(&result);
        assert!(summary.contains("Found 1 credentials"));
        assert!(summary.contains("HIGH"));
    }

    #[test]
    fn test_credential_pattern_struct() {
        let pattern = CredentialPattern {
            name: "Test".to_string(),
            pattern: "test".to_string(),
            category: "test".to_string(),
            severity: "LOW".to_string(),
            description: "Test pattern".to_string(),
        };
        assert_eq!(pattern.name, "Test");
    }

    #[test]
    fn test_found_credential_struct() {
        let cred = FoundCredential {
            pattern_name: "Test".to_string(),
            file_path: "test.txt".to_string(),
            line_number: 1,
            matched_text: "test".to_string(),
            context: "test context".to_string(),
            severity: "LOW".to_string(),
        };
        assert_eq!(cred.line_number, 1);
    }
}