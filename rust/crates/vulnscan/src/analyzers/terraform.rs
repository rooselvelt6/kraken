use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use std::path::Path;

pub struct TerraformAnalyzer;

impl Default for TerraformAnalyzer {
    fn default() -> Self {
        Self
    }
}

impl super::LanguageAnalyzer for TerraformAnalyzer {
    fn language(&self) -> Language {
        Language::Terraform
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["tf"]
    }

    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let lineno = i as u32 + 1;

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let lower = trimmed.to_lowercase();

            if lower.contains("acl") && (lower.contains("public-read") || lower.contains("public-read-write"))
                && !lower.starts_with("#") && !lower.starts_with("//") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-200",
                        "S3 bucket with public read ACL",
                        "Setting ACL to public-read or public-read-write exposes the bucket to the internet. Use private ACL with pre-signed URLs for access.",
                        0.9,
                    ));
                }

            if lower.contains("effect") && lower.contains("\"allow\"") && lower.contains("action") && lower.contains("\"*\"") || (lower.contains("actions") && lower.contains("[\"*\"]") || lower.contains("actions") && lower.contains("[\"*\"") || lower.contains("action") && lower.contains("[\"*\"]")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-732",
                    "IAM policy with wildcard action (*)",
                    "IAM policies should not use `*` as action. Use least-privilege with specific actions (e.g. s3:GetObject, ec2:DescribeInstances).",
                    0.95,
                ));
            }

            if lower.contains("cidr_blocks") && (lower.contains("\"0.0.0.0/0\"") || lower.contains("[\"0.0.0.0/0\"]")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-200",
                    "Security group open to world (0.0.0.0/0)",
                    "Avoid 0.0.0.0/0 in security group ingress rules. Restrict to specific IP ranges or use security group references.",
                    0.95,
                ));
            }

            if lower.contains("ingress") && (lower.contains("from_port") || lower.contains("from_port")) && lower.contains("0") && lower.contains("to_port") && lower.contains("0") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-200",
                    "Security group allows all ports (0-0)",
                    "Opening all ports (0-0) in ingress rules exposes the resource unnecessarily. Specify only the required ports.",
                    0.85,
                ));
            }

            if lower.contains("admin") && (lower.contains("= true") || lower.contains("=\"true\"")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-732",
                    "Admin privilege set to true",
                    "Setting admin = true grants full administrative privileges. Use least-privilege with specific roles/permissions.",
                    0.85,
                ));
            }

            let secret_kws = ["password", "secret", "token", "api_key", "apikey", "private_key", "access_key"];
            if secret_kws.iter().any(|kw| lower.contains(kw)) && (lower.contains("= \"") || lower.contains("=  \"")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-798",
                    "Hardcoded secret in Terraform variable",
                    "Avoid hardcoding secrets in .tf files. Use Terraform variables with sensitive=true and external secret stores (Vault, AWS Secrets Manager, etc.).",
                    0.9,
                ));
            }

            if lower.contains("version") && !lower.contains("required_version") && !lower.contains("terraform")
                && (lower.contains("= \"~>") || lower.contains("= \">=") || lower.contains("= \"<") || lower.contains("latest")) {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Medium,
                        "CWE-1104",
                        "Unpinned provider version constraint",
                        "Pin provider version with specific version (e.g. version = \"4.0.0\") instead of fuzzy constraints (~>, >=) to ensure reproducible builds.",
                        0.75,
                    ));
                }

            if lower.starts_with("provider ") && lower.contains("\"")
                && !lower.contains("version") && !lower.contains("required_providers") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Medium,
                        "CWE-1104",
                        "Provider without version constraint",
                        "Add version constraint for provider to ensure reproducible infrastructure. Use `required_providers` block with pinned versions.",
                        0.8,
                    ));
                }

            if (lower.contains("source  = \"hashicorp/") || lower.contains("source = \"hashicorp/"))
                && !lower.contains("version") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Medium,
                        "CWE-1104",
                        "Provider without version constraint",
                        "Add version constraint for provider to ensure reproducible infrastructure. Use `required_providers` block with pinned versions.",
                        0.8,
                    ));
                }

            if lower.contains("backend") && lower.contains("s3") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Info,
                    "CWE-200",
                    "S3 backend for state file",
                    "Ensure S3 backend has versioning enabled, server-side encryption, and DynamoDB for state locking to protect Terraform state.",
                    0.5,
                ));
            }
        }

        findings
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    file_path: &Path,
    line_number: u32,
    snippet: &str,
    severity: Severity,
    cwe: &str,
    title: &str,
    remediation: &str,
    confidence: f32,
) -> Finding {
    Finding {
        id: crate::new_finding_id(),
        severity,
        cwe: Some(cwe.to_string()),
        cve: None,
        description: format!("{} — {}", title, cwe),
        file_path: Some(file_path.to_path_buf()),
        line_number: Some(line_number),
        vulnerable_code_snippet: Some(snippet.trim().to_string()),
        remediation: Some(remediation.to_string()),
        confidence,
        discovery_method: DiscoveryMethod::StaticPatternMatching,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::LanguageAnalyzer;
    use std::path::PathBuf;

    fn analyze(content: &str) -> Vec<Finding> {
        let analyzer = TerraformAnalyzer;
        analyzer.analyze(content, &PathBuf::from("main.tf"), &ScanConfig::default())
    }

    #[test]
    fn test_s3_public_read() {
        let content = r#"resource "aws_s3_bucket_acl" "bucket" {
  bucket = my-bucket
  acl    = "public-read"
}"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200") && f.description.contains("S3")));
    }

    #[test]
    fn test_iam_wildcard_action() {
        let content = r#"resource "aws_iam_policy" "policy" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
    }]
  })
}"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-732")));
    }

    #[test]
    fn test_security_group_open_world() {
        let content = r#"resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200") && f.description.contains("Security group open")));
    }

    #[test]
    fn test_hardcoded_secret() {
        let content = r#"variable "db_password" {
  default = "supersecret123"
}"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-798")));
    }

    #[test]
    fn test_admin_true() {
        let content = r#"resource "aws_iam_role" "admin" {
  name = "admin-role"
  admin = true
}"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-732") && f.description.contains("Admin")));
    }

    #[test]
    fn test_unpinned_provider() {
        let content = r#"provider "aws" {
  region = "us-east-1"
}"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-1104")));
    }

    #[test]
    fn test_secure_tf_ok() {
        let content = r#"terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.0.0"
    }
  }
  backend "s3" {
    bucket = "tf-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_s3_bucket_acl" "bucket" {
  bucket = my-bucket
  acl    = "private"
}

resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_iam_policy" "policy" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
"#;
        let findings = analyze(content);
        let high_or_critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High || f.severity == Severity::Critical).collect();
        assert!(high_or_critical.is_empty(), "Secure TF should not have High/Critical findings, got: {:?}", high_or_critical);
    }
}
