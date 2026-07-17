

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IamUser {
    pub username: String,
    pub arn: String,
    pub policies: Vec<String>,
    pub attached_policies: Vec<String>,
    pub groups: Vec<String>,
    pub access_keys: Vec<AccessKey>,
    pub mfa_enabled: bool,
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessKey {
    pub key_id: String,
    pub status: String,
    pub created: Option<String>,
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IamFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub resource: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IamAuditResult {
    pub users: Vec<IamUser>,
    pub findings: Vec<IamFinding>,
    pub total_users: usize,
    pub users_without_mfa: usize,
    pub unused_keys: usize,
    pub over_permissive_policies: usize,
}

pub struct IamAuditor;

impl Default for IamAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl IamAuditor {
    pub fn new() -> Self {
        IamAuditor
    }

    pub fn analyze_policy_document(policy_json: &str) -> Vec<IamFinding> {
        let mut findings = Vec::new();
        if let Ok(doc) = serde_json::from_str::<serde_json::Value>(policy_json) {
            let statement = doc.get("Statement").and_then(|s| s.as_array());
            if let Some(statements) = statement {
                for stmt in statements {
                    let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
                    let action = stmt.get("Action").and_then(|a| a.as_str()).unwrap_or("");
                    let resource = stmt.get("Resource").and_then(|r| r.as_str()).unwrap_or("");

                    if effect == "Allow" && action == "*" {
                        findings.push(IamFinding {
                            severity: "CRITICAL".to_string(),
                            category: "Overly Permissive".to_string(),
                            description: "IAM policy allows all actions (*)".to_string(),
                            resource: resource.to_string(),
                            recommendation: "Principle of least privilege: scope actions to only what's needed".to_string(),
                        });
                    }
                    if effect == "Allow" && resource == "*" {
                        findings.push(IamFinding {
                            severity: "HIGH".to_string(),
                            category: "Wide Resource Access".to_string(),
                            description: "IAM policy grants access to all resources (*)".to_string(),
                            resource: resource.to_string(),
                            recommendation: "Scope resources to specific ARNs".to_string(),
                        });
                    }
                }
            }
        }
        findings
    }

    pub fn audit_users(users: &[IamUser]) -> IamAuditResult {
        let total_users = users.len();
        let users_without_mfa = users.iter().filter(|u| !u.mfa_enabled).count();
        let mut unused_keys = 0;
        let over_permissive = 0;
        let mut findings = Vec::new();

        for user in users {
            for key in &user.access_keys {
                if key.status == "Inactive" || key.last_used.is_none() {
                    unused_keys += 1;
                    findings.push(IamFinding {
                        severity: "MEDIUM".to_string(),
                        category: "Unused Access Key".to_string(),
                        description: format!("Access key {} for {} is unused", key.key_id, user.username),
                        resource: user.arn.clone(),
                        recommendation: "Rotate and remove unused access keys".to_string(),
                    });
                }
            }
            if !user.mfa_enabled {
                findings.push(IamFinding {
                    severity: "HIGH".to_string(),
                    category: "MFA Not Enabled".to_string(),
                    description: format!("User {} does not have MFA enabled", user.username),
                    resource: user.arn.clone(),
                    recommendation: "Enable MFA for all users".to_string(),
                });
            }
        }

        IamAuditResult {
            users: users.to_vec(),
            findings,
            total_users,
            users_without_mfa,
            unused_keys,
            over_permissive_policies: over_permissive,
        }
    }

    pub fn check_cloudtrail(policy_json: &str) -> Vec<IamFinding> {
        let mut findings = Vec::new();
        if let Ok(doc) = serde_json::from_str::<serde_json::Value>(policy_json) {
            if let Some(statement) = doc.get("Statement").and_then(|s| s.as_array()) {
                for stmt in statement {
                    if let Some(condition) = stmt.get("Condition") {
                        if condition.to_string().contains("aws:MultiFactorAuthAge") {
                            findings.push(IamFinding {
                                severity: "INFO".to_string(),
                                category: "MFA Condition Found".to_string(),
                                description: "Policy uses aws:MultiFactorAuthAge condition".to_string(),
                                resource: "policy".to_string(),
                                recommendation: "Verify MFA age threshold is appropriate".to_string(),
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_overly_permissive() {
        let policy = r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        let findings = IamAuditor::analyze_policy_document(policy);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == "CRITICAL"));
    }

    #[test]
    fn test_analyze_safe_policy() {
        let policy = r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}"#;
        let findings = IamAuditor::analyze_policy_document(policy);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_users() {
        let users = vec![
            IamUser {
                username: "admin".to_string(),
                arn: "arn:aws:iam::123:user/admin".to_string(),
                policies: vec![],
                attached_policies: vec![],
                groups: vec![],
                access_keys: vec![],
                mfa_enabled: false,
                last_used: None,
            },
            IamUser {
                username: "dev".to_string(),
                arn: "arn:aws:iam::123:user/dev".to_string(),
                policies: vec![],
                attached_policies: vec![],
                groups: vec![],
                access_keys: vec![AccessKey {
                    key_id: "AKIA123".to_string(),
                    status: "Active".to_string(),
                    created: None,
                    last_used: None,
                }],
                mfa_enabled: true,
                last_used: None,
            },
        ];
        let result = IamAuditor::audit_users(&users);
        assert_eq!(result.users_without_mfa, 1);
        assert_eq!(result.unused_keys, 1);
    }

    #[test]
    fn test_check_cloudtrail() {
        let policy = r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}]}"#;
        let findings = IamAuditor::check_cloudtrail(policy);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_iam_user() {
        let u = IamUser {
            username: "test".to_string(),
            arn: "arn:aws:iam::123:user/test".to_string(),
            policies: vec![],
            attached_policies: vec![],
            groups: vec![],
            access_keys: vec![],
            mfa_enabled: true,
            last_used: None,
        };
        let json = serde_json::to_string_pretty(&u).unwrap();
        assert!(json.contains("arn:aws:iam"));
    }
}
