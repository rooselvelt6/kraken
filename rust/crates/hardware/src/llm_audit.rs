use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAuditConfig {
    pub model: String,
    pub max_tokens: usize,
    pub temperature: f64,
    pub focus_areas: Vec<String>,
}

impl Default for LlmAuditConfig {
    fn default() -> Self {
        LlmAuditConfig {
            model: "claude-3-5-sonnet-20241022".to_string(),
            max_tokens: 4096,
            temperature: 0.3,
            focus_areas: vec![
                "security".to_string(),
                "vulnerabilities".to_string(),
                "hardcoded_secrets".to_string(),
                "insecure_configurations".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareAuditRequest {
    pub firmware_info: FirmwareInfo,
    pub file_samples: Vec<FileSample>,
    pub config: LlmAuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareInfo {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    pub filesystems: Vec<String>,
    pub architecture: Option<String>,
    pub kernel_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSample {
    pub path: String,
    pub size: u64,
    pub content_preview: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareAuditResult {
    pub summary: String,
    pub findings: Vec<AuditFinding>,
    pub recommendations: Vec<String>,
    pub risk_score: f64,
    pub categories: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub title: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub recommendation: String,
    pub cwe: Option<String>,
}

pub struct LlmFirmwareAuditor;

impl Default for LlmFirmwareAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmFirmwareAuditor {
    pub fn new() -> Self {
        LlmFirmwareAuditor
    }

    pub fn build_audit_prompt(request: &FirmwareAuditRequest) -> String {
        let mut prompt = format!(
            "Analyze this firmware image for security vulnerabilities and issues:\n\n\
             Firmware: {} ({} bytes)\n\
             Entropy: {:.2}\n\
             Filesystems: {}\n",
            request.firmware_info.name,
            request.firmware_info.size,
            request.firmware_info.entropy,
            request.firmware_info.filesystems.join(", ")
        );

        if let Some(ref arch) = request.firmware_info.architecture {
            prompt.push_str(&format!("Architecture: {}\n", arch));
        }
        if let Some(ref kernel) = request.firmware_info.kernel_version {
            prompt.push_str(&format!("Kernel: {}\n", kernel));
        }

        prompt.push_str("\nFile samples analyzed:\n");
        for sample in &request.file_samples {
            prompt.push_str(&format!(
                "\n--- {} ({} bytes, {}) ---\n{}\n",
                sample.path, sample.size, sample.file_type, sample.content_preview
            ));
        }

        prompt.push_str(&format!(
            "\nFocus areas: {}\n",
            request.config.focus_areas.join(", ")
        ));

        prompt.push_str(
            "\nProvide a JSON response with:\n\
             1. summary: Overall security assessment\n\
             2. findings: Array of {title, severity, category, description, evidence, recommendation, cwe}\n\
             3. recommendations: Array of remediation steps\n\
             4. risk_score: 0.0-1.0\n\
             5. categories: Map of category to finding titles"
        );

        prompt
    }

    pub fn parse_audit_response(response: &str) -> Result<FirmwareAuditResult, String> {
        let json_str = if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                &response[start..=end]
            } else {
                response
            }
        } else {
            response
        };

        serde_json::from_str::<FirmwareAuditResult>(json_str)
            .map_err(|e| format!("Failed to parse audit response: {}", e))
    }

    pub fn create_firmware_info(
        name: &str,
        data: &[u8],
        filesystems: Vec<String>,
    ) -> FirmwareInfo {
        let entropy = crate::firmware::FirmwareExtractor::calculate_entropy(data);
        FirmwareInfo {
            name: name.to_string(),
            size: data.len() as u64,
            entropy,
            filesystems,
            architecture: None,
            kernel_version: None,
        }
    }

    pub fn extract_file_samples(data: &[u8], max_samples: usize) -> Vec<FileSample> {
        let mut samples = Vec::new();
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.lines().collect();

        for (i, chunk) in lines.chunks(100).enumerate().take(max_samples) {
            let preview = chunk.join("\n");
            if !preview.trim().is_empty() {
                samples.push(FileSample {
                    path: format!("chunk_{}", i),
                    size: preview.len() as u64,
                    content_preview: preview.chars().take(500).collect(),
                    file_type: "text".to_string(),
                });
            }
        }

        samples
    }

    pub fn summarize_findings(findings: &[AuditFinding]) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        for finding in findings {
            *summary.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        summary
    }

    pub fn calculate_risk_score(findings: &[AuditFinding]) -> f64 {
        if findings.is_empty() {
            return 0.0;
        }

        let total = findings.len() as f64;
        let critical = findings.iter().filter(|f| f.severity == "CRITICAL").count() as f64;
        let high = findings.iter().filter(|f| f.severity == "HIGH").count() as f64;
        let medium = findings.iter().filter(|f| f.severity == "MEDIUM").count() as f64;

        let score = (critical * 1.0 + high * 0.7 + medium * 0.3) / total;
        score.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LlmAuditConfig::default();
        assert_eq!(config.model, "claude-3-5-sonnet-20241022");
        assert_eq!(config.max_tokens, 4096);
    }

    #[test]
    fn test_build_audit_prompt() {
        let request = FirmwareAuditRequest {
            firmware_info: FirmwareInfo {
                name: "test.bin".to_string(),
                size: 1024,
                entropy: 7.5,
                filesystems: vec!["SquashFS".to_string()],
                architecture: Some("ARM".to_string()),
                kernel_version: Some("4.19".to_string()),
            },
            file_samples: vec![],
            config: LlmAuditConfig::default(),
        };
        let prompt = LlmFirmwareAuditor::build_audit_prompt(&request);
        assert!(prompt.contains("test.bin"));
        assert!(prompt.contains("ARM"));
        assert!(prompt.contains("4.19"));
    }

    #[test]
    fn test_parse_audit_response() {
        let response = r#"{
            "summary": "Firmware has security issues",
            "findings": [
                {
                    "title": "Hardcoded password",
                    "severity": "HIGH",
                    "category": "credentials",
                    "description": "Default password found",
                    "evidence": "admin:admin in /etc/shadow",
                    "recommendation": "Change default credentials",
                    "cwe": "CWE-798"
                }
            ],
            "recommendations": ["Change default passwords"],
            "risk_score": 0.7,
            "categories": {"credentials": ["Hardcoded password"]}
        }"#;
        let result = LlmFirmwareAuditor::parse_audit_response(response).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.risk_score, 0.7);
    }

    #[test]
    fn test_parse_audit_response_with_markdown() {
        let response = r#"Here's the analysis:

```json
{
    "summary": "Test",
    "findings": [],
    "recommendations": [],
    "risk_score": 0.0,
    "categories": {}
}
```"#;
        let result = LlmFirmwareAuditor::parse_audit_response(response).unwrap();
        assert_eq!(result.summary, "Test");
    }

    #[test]
    fn test_create_firmware_info() {
        let data = b"test firmware data";
        let info = LlmFirmwareAuditor::create_firmware_info("test.bin", data, vec!["SquashFS".to_string()]);
        assert_eq!(info.name, "test.bin");
        assert_eq!(info.size, 18);
        assert!(!info.filesystems.is_empty());
    }

    #[test]
    fn test_extract_file_samples() {
        let data = b"line1\nline2\nline3\nline4\nline5";
        let samples = LlmFirmwareAuditor::extract_file_samples(data, 2);
        assert!(!samples.is_empty());
        assert!(samples.len() <= 2);
    }

    #[test]
    fn test_summarize_findings() {
        let findings = vec![
            AuditFinding {
                title: "Test1".to_string(),
                severity: "HIGH".to_string(),
                category: "test".to_string(),
                description: "test".to_string(),
                evidence: "test".to_string(),
                recommendation: "test".to_string(),
                cwe: None,
            },
            AuditFinding {
                title: "Test2".to_string(),
                severity: "LOW".to_string(),
                category: "test".to_string(),
                description: "test".to_string(),
                evidence: "test".to_string(),
                recommendation: "test".to_string(),
                cwe: None,
            },
        ];
        let summary = LlmFirmwareAuditor::summarize_findings(&findings);
        assert_eq!(summary.get("HIGH"), Some(&1));
        assert_eq!(summary.get("LOW"), Some(&1));
    }

    #[test]
    fn test_calculate_risk_score_empty() {
        let findings = vec![];
        let score = LlmFirmwareAuditor::calculate_risk_score(&findings);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_calculate_risk_score_high() {
        let findings = vec![
            AuditFinding {
                title: "Critical".to_string(),
                severity: "CRITICAL".to_string(),
                category: "test".to_string(),
                description: "test".to_string(),
                evidence: "test".to_string(),
                recommendation: "test".to_string(),
                cwe: None,
            },
            AuditFinding {
                title: "High".to_string(),
                severity: "HIGH".to_string(),
                category: "test".to_string(),
                description: "test".to_string(),
                evidence: "test".to_string(),
                recommendation: "test".to_string(),
                cwe: None,
            },
        ];
        let score = LlmFirmwareAuditor::calculate_risk_score(&findings);
        assert!(score >= 0.8);
    }

    #[test]
    fn test_calculate_risk_score_low() {
        let findings = vec![
            AuditFinding {
                title: "Low".to_string(),
                severity: "LOW".to_string(),
                category: "test".to_string(),
                description: "test".to_string(),
                evidence: "test".to_string(),
                recommendation: "test".to_string(),
                cwe: None,
            },
            AuditFinding {
                title: "Info".to_string(),
                severity: "INFO".to_string(),
                category: "test".to_string(),
                description: "test".to_string(),
                evidence: "test".to_string(),
                recommendation: "test".to_string(),
                cwe: None,
            },
        ];
        let score = LlmFirmwareAuditor::calculate_risk_score(&findings);
        assert!(score < 0.3);
    }
}