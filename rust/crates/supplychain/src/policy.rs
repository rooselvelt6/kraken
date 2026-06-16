use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub name: String,
    pub version: String,
    pub rules: Vec<PolicyRule>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub c_type: String,
    pub condition: String,
    pub action: PolicyAction,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Warn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvalResult {
    pub policy: String,
    pub total_rules: usize,
    pub passed: usize,
    pub failed: usize,
    pub violations: Vec<PolicyViolation>,
    pub compliant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule_id: String,
    pub rule_name: String,
    pub message: String,
    pub action: PolicyAction,
}

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        PolicyEngine
    }

    pub fn default_policy() -> PolicyConfig {
        PolicyConfig {
            name: "kraken-default".to_string(),
            version: "1.0".to_string(),
            severity: "medium".to_string(),
            rules: vec![
                PolicyRule {
                    id: "SC-001".to_string(),
                    name: "No known critical vulnerabilities".to_string(),
                    c_type: "vulnerability".to_string(),
                    condition: "max_severity < CRITICAL".to_string(),
                    action: PolicyAction::Deny,
                    severity: "high".to_string(),
                },
                PolicyRule {
                    id: "SC-002".to_string(),
                    name: "No restricted licenses".to_string(),
                    c_type: "license".to_string(),
                    condition: "no_gpl_or_agpl".to_string(),
                    action: PolicyAction::Deny,
                    severity: "high".to_string(),
                },
                PolicyRule {
                    id: "SC-003".to_string(),
                    name: "SBOM must exist".to_string(),
                    c_type: "sbom".to_string(),
                    condition: "sbom_present".to_string(),
                    action: PolicyAction::Deny,
                    severity: "medium".to_string(),
                },
                PolicyRule {
                    id: "SC-004".to_string(),
                    name: "SLSA level >= 1".to_string(),
                    c_type: "slsa".to_string(),
                    condition: "slsa_level >= 1".to_string(),
                    action: PolicyAction::Warn,
                    severity: "low".to_string(),
                },
                PolicyRule {
                    id: "SC-005".to_string(),
                    name: "No deprecated dependencies".to_string(),
                    c_type: "dependency".to_string(),
                    condition: "no_deprecated".to_string(),
                    action: PolicyAction::Warn,
                    severity: "medium".to_string(),
                },
            ],
        }
    }

    pub fn evaluate(policy: &PolicyConfig, findings: &[(&str, bool)]) -> PolicyEvalResult {
        let mut violations = Vec::new();
        let mut passed = 0usize;

        for rule in &policy.rules {
            let matched = findings.iter().find(|&&(id, _)| id == rule.id);
            let is_violation = match matched {
                Some(&(_, result)) => !result,
                None => true,
            };

            if is_violation {
                violations.push(PolicyViolation {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    message: format!("Policy violation: {}", rule.condition),
                    action: rule.action.clone(),
                });
            } else {
                passed += 1;
            }
        }

        let failed = violations.len();
        let has_deny = violations.iter().any(|v| v.action == PolicyAction::Deny);

        PolicyEvalResult {
            policy: policy.name.clone(),
            total_rules: policy.rules.len(),
            passed,
            failed,
            violations,
            compliant: !has_deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = PolicyEngine::default_policy();
        assert_eq!(policy.rules.len(), 5);
    }

    #[test]
    fn test_evaluate_all_pass() {
        let policy = PolicyEngine::default_policy();
        let findings = vec![
            ("SC-001", true),
            ("SC-002", true),
            ("SC-003", true),
            ("SC-004", true),
            ("SC-005", true),
        ];
        let result = PolicyEngine::evaluate(&policy, &findings);
        assert!(result.compliant);
        assert_eq!(result.passed, 5);
    }

    #[test]
    fn test_evaluate_with_violations() {
        let policy = PolicyEngine::default_policy();
        let findings = vec![
            ("SC-001", false),
            ("SC-002", true),
            ("SC-003", true),
            ("SC-004", true),
            ("SC-005", true),
        ];
        let result = PolicyEngine::evaluate(&policy, &findings);
        assert!(!result.compliant);
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_evaluate_empty_findings() {
        let policy = PolicyEngine::default_policy();
        let result = PolicyEngine::evaluate(&policy, &[]);
        assert!(!result.compliant);
        assert_eq!(result.failed, 5);
    }

    #[test]
    fn test_policy_serde() {
        let policy = PolicyEngine::default_policy();
        let result = PolicyEngine::evaluate(&policy, &[]);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("SC-001"));
    }
}
