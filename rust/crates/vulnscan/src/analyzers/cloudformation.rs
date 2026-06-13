use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use std::path::Path;

pub struct CloudFormationAnalyzer;

impl Default for CloudFormationAnalyzer {
    fn default() -> Self {
        Self
    }
}

impl super::LanguageAnalyzer for CloudFormationAnalyzer {
    fn language(&self) -> Language {
        Language::Terraform
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["yaml", "yml", "json"]
    }

    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let lineno = i as u32 + 1;

            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            let lower = trimmed.to_lowercase();

            if lower.contains("action") && (lower.contains("\"*\"") || lower.contains("\"*\":") || lower.contains("'*'")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-732",
                    "IAM policy with wildcard action (*)",
                    "CloudFormation IAM policies should not use `*` as action. Use least-privilege with specific actions for each resource.",
                    0.95,
                ));
            }

            if lower.contains("0.0.0.0/0") && (lower.contains("cidr") || lower.contains("cidrip") || lower.contains("cidr_ip")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-200",
                    "Security group open to world (0.0.0.0/0)",
                    "Avoid 0.0.0.0/0 in security group ingress rules. Restrict to specific IP ranges or use security group references.",
                    0.95,
                ));
            }

            if lower.contains("public-read") && (lower.contains("acl") || lower.contains("accesscontrol")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-200",
                    "S3 bucket with public read ACL",
                    "Setting public-read ACL exposes the bucket to the internet. Use private ACL with pre-signed URLs for access.",
                    0.9,
                ));
            }
            if lower == "      accesscontrol: publicread" || lower.contains("publicread") && lower.contains("accesscontrol") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-200",
                    "S3 bucket with public read ACL",
                    "Setting PublicRead ACL exposes the bucket to the internet. Use private ACL with pre-signed URLs for access.",
                    0.9,
                ));
            }

            let secret_kws = ["password", "secret", "token", "api_key", "apikey", "private_key", "access_key"];
            if secret_kws.iter().any(|kw| lower.contains(kw)) && lower.contains(": \"") {
                if !lower.contains("ssm") && !lower.contains("secretsmanager") && !lower.contains("aws::ssm") && !lower.contains("resolve:ssm") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-798",
                        "Possible hardcoded secret in CloudFormation",
                        "Avoid hardcoding secrets in CloudFormation templates. Use AWS Secrets Manager, SSM Parameter Store with dynamic references, or Parameter Store secure strings.",
                        0.85,
                    ));
                }
            }

            if lower.contains("password") && !lower.contains("secretsmanager") {
                if (lower.contains("masteruserpassword") || lower.contains("masterpassword")) && lower.contains(": \"") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Medium,
                        "CWE-521",
                        "Database password without Secrets Manager",
                        "Consider using AWS Secrets Manager for database passwords instead of plaintext in CloudFormation templates or Parameter Store.",
                        0.8,
                    ));
                }
            }
        }

        findings
    }
}

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
        let analyzer = CloudFormationAnalyzer;
        analyzer.analyze(content, &PathBuf::from("template.yaml"), &ScanConfig::default())
    }

    #[test]
    fn test_iam_wildcard() {
        let content = r#"Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-732")));
    }

    #[test]
    fn test_security_group_open_world() {
        let content = r#"Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
          IpProtocol: tcp
"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200") && f.description.contains("Security group open")));
    }

    #[test]
    fn test_public_read_acl() {
        let content = r#"Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200") && f.description.contains("S3")));
    }

    #[test]
    fn test_hardcoded_secret() {
        let content = r#"Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterPassword: "supersecret123"
"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-798")));
    }

    #[test]
    fn test_db_password_without_secrets_manager() {
        let content = r#"Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUsername: admin
      MasterUserPassword: "password123"
      DBInstanceIdentifier: mydb
"#;
        let findings = analyze(content);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-521")));
    }

    #[test]
    fn test_secure_template_ok() {
        let content = r#"
Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 10.0.0.0/8
          FromPort: 22
          ToPort: 22
          IpProtocol: tcp

  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
"#;
        let findings = analyze(content);
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        assert!(critical.is_empty(), "Secure template should not have Critical findings, got: {:?}", critical);
    }
}
