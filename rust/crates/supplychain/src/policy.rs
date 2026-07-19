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

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        PolicyEngine
    }

    /// Returns the default supply chain policy with 5 rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use supplychain::PolicyEngine;
    ///
    /// let policy = PolicyEngine::default_policy();
    /// assert_eq!(policy.rules.len(), 5);
    /// assert_eq!(policy.name, "kraken-default");
    /// ```
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

    /// Evaluates a policy against a set of findings.
    ///
    /// # Examples
    ///
    /// ```
    /// use supplychain::PolicyEngine;
    ///
    /// let policy = PolicyEngine::default_policy();
    /// let findings = vec![
    ///     ("SC-001", true),
    ///     ("SC-002", true),
    ///     ("SC-003", true),
    ///     ("SC-004", true),
    ///     ("SC-005", true),
    /// ];
    /// let result = PolicyEngine::evaluate(&policy, &findings);
    /// assert!(result.compliant);
    /// assert_eq!(result.passed, 5);
    /// ```
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

    #[test]
    fn test_evaluate_partial_pass() {
        let policy = PolicyEngine::default_policy();
        let findings = vec![
            ("SC-001", true),
            ("SC-002", true),
            ("SC-003", false),
            ("SC-004", false),
            ("SC-005", true),
        ];
        let result = PolicyEngine::evaluate(&policy, &findings);
        assert_eq!(result.passed, 3);
        assert_eq!(result.failed, 2);
    }

    #[test]
    fn test_evaluate_compliant_if_only_warn_violations() {
        let policy = PolicyConfig {
            name: "test".to_string(),
            version: "1.0".to_string(),
            severity: "low".to_string(),
            rules: vec![
                PolicyRule {
                    id: "W1".to_string(),
                    name: "Warn only".to_string(),
                    c_type: "test".to_string(),
                    condition: "test".to_string(),
                    action: PolicyAction::Warn,
                    severity: "low".to_string(),
                },
            ],
        };
        let findings = vec![("W1", false)];
        let result = PolicyEngine::evaluate(&policy, &findings);
        assert!(result.compliant);
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_policy_default_has_5_rules() {
        let policy = PolicyEngine::default_policy();
        assert_eq!(policy.rules.len(), 5);
        assert_eq!(policy.name, "kraken-default");
        assert_eq!(policy.version, "1.0");
    }

    #[test]
    fn test_policy_violation_struct() {
        let v = PolicyViolation {
            rule_id: "R1".to_string(),
            rule_name: "Test Rule".to_string(),
            message: "violation".to_string(),
            action: PolicyAction::Deny,
        };
        assert_eq!(v.action, PolicyAction::Deny);
    }

    #[test]
    fn test_policy_action_variants() {
        assert_eq!(PolicyAction::Allow, PolicyAction::Allow);
        assert_eq!(PolicyAction::Deny, PolicyAction::Deny);
        assert_eq!(PolicyAction::Warn, PolicyAction::Warn);
        assert_ne!(PolicyAction::Allow, PolicyAction::Deny);
    }

    #[test]
    fn test_eval_result_struct() {
        let result = PolicyEvalResult {
            policy: "test".to_string(),
            total_rules: 5,
            passed: 3,
            failed: 2,
            violations: vec![],
            compliant: true,
        };
        assert!(result.compliant);
        assert_eq!(result.total_rules, 5);
    }

    #[test]
    fn test_policy_rule_struct() {
        let rule = PolicyRule {
            id: "R1".to_string(),
            name: "Test".to_string(),
            c_type: "vulnerability".to_string(),
            condition: "severity < high".to_string(),
            action: PolicyAction::Warn,
            severity: "medium".to_string(),
        };
        assert_eq!(rule.c_type, "vulnerability");
    }

    #[test]
    fn test_evaluate_unknown_rule_id() {
        let policy = PolicyEngine::default_policy();
        let findings = vec![("UNKNOWN-ID", true)];
        let result = PolicyEngine::evaluate(&policy, &findings);
        assert_eq!(result.failed, 5);
        assert!(!result.compliant);
    }

    #[test]
    fn test_policy_engine_default() {
        let engine = PolicyEngine::default();
        let policy = PolicyEngine::default_policy();
        let result = PolicyEngine::evaluate(&policy, &[]);
        assert_eq!(result.total_rules, 5);
    }
}
