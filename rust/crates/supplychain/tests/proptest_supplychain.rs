#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;
use supplychain::{LicenseChecker, PolicyEngine, TyposquatDetector};

fn arb_known_license() -> impl Strategy<Value = (String, String, String)> {
    ("[a-z]{2,10}", "[0-9]+\\.[0-9]+", "(MIT|Apache-2.0|GPL-3.0-only|ISC|BSD-2-Clause)")
}

proptest! {
    #[test]
    fn license_audit_total_equals_categories(
        deps in prop::collection::vec(arb_known_license(), 0..50),
    ) {
        let refs: Vec<(&str, &str, &str)> = deps.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str())).collect();
        let audit = LicenseChecker::audit(&refs);
        prop_assert_eq!(
            audit.total_dependencies,
            audit.allowed.len() + audit.restricted.len() + audit.unknown.len(),
            "total should equal sum of categories"
        );
    }

    #[test]
    fn license_audit_total_matches_input(deps in prop::collection::vec(
        ("[a-z]{2,10}", "[0-9]+\\.[0-9]+", "MIT"),
        0..100,
    )) {
        let refs: Vec<(&str, &str, &str)> = deps.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str())).collect();
        let audit = LicenseChecker::audit(&refs);
        prop_assert_eq!(audit.total_dependencies, refs.len());
    }

    #[test]
    fn license_audit_compliance_bounded(deps in prop::collection::vec(
        ("[a-z]{2,10}", "[0-9]+\\.[0-9]+", "(MIT|GPL-3.0-only|ISC)"),
        0..100,
    )) {
        let refs: Vec<(&str, &str, &str)> = deps.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str())).collect();
        let audit = LicenseChecker::audit(&refs);
        prop_assert!(audit.compliance_pct >= 0.0);
        prop_assert!(audit.compliance_pct <= 100.0);
    }

    #[test]
    fn license_audit_gpl_is_restricted(gpl_name in "[a-z]{2,15}") {
        let deps = [(gpl_name.as_str(), "1.0", "GPL-3.0-only")];
        let audit = LicenseChecker::audit(&deps);
        prop_assert_eq!(audit.restricted.len(), 1);
        prop_assert_eq!(audit.compliance_pct, 0.0);
    }

    #[test]
    fn typosquat_check_returns_input_name(name in "[a-zA-Z0-9_-]{1,50}") {
        let result = TyposquatDetector::check(&name);
        prop_assert_eq!(result.package, name);
    }

    #[test]
    fn typosquat_risk_level_is_valid(name in "[a-zA-Z0-9_-]{1,50}") {
        let result = TyposquatDetector::check(&name);
        prop_assert!(
            result.risk_level == "LOW" || result.risk_level == "MEDIUM" || result.risk_level == "HIGH",
            "risk_level should be LOW, MEDIUM, or HIGH, got: {}",
            result.risk_level
        );
    }

    #[test]
    fn typosquat_total_suspicious_matches_count(name in "[a-zA-Z0-9_-]{1,50}") {
        let result = TyposquatDetector::check(&name);
        prop_assert_eq!(result.total_suspicious, result.matches.len());
    }

    #[test]
    fn policy_all_pass_is_compliant(rule_ids in prop::collection::vec("SC-00[1-5]", 0..5)) {
        let policy = PolicyEngine::default_policy();
        let mut seen = std::collections::HashSet::new();
        let mut findings: Vec<(&str, bool)> = Vec::new();
        for id in &rule_ids {
            if seen.insert(id.as_str()) {
                findings.push((id.as_str(), true));
            }
        }
        let result = PolicyEngine::evaluate(&policy, &findings);
        prop_assert_eq!(result.passed, findings.len());
        prop_assert_eq!(result.failed, policy.rules.len() - findings.len());
    }

    #[test]
    fn policy_violated_rules_always_fail(
        violated_ids in prop::collection::vec("SC-00[1-5]", 1..5),
    ) {
        let policy = PolicyEngine::default_policy();
        let mut seen = std::collections::HashSet::new();
        let mut findings: Vec<(&str, bool)> = Vec::new();
        for id in &violated_ids {
            if seen.insert(id.as_str()) {
                findings.push((id.as_str(), false));
            }
        }
        let result = PolicyEngine::evaluate(&policy, &findings);
        prop_assert!(result.failed >= findings.len(), "failed ({}) should be >= findings ({})", result.failed, findings.len());
        prop_assert!(!result.compliant);
    }
}

#[test]
fn default_policy_has_five_rules() {
    let policy = PolicyEngine::default_policy();
    assert_eq!(policy.rules.len(), 5);
}

#[test]
fn policy_no_findings_all_fail() {
    let policy = PolicyEngine::default_policy();
    let findings: Vec<(&str, bool)> = vec![];
    let result = PolicyEngine::evaluate(&policy, &findings);
    assert_eq!(result.passed, 0);
    assert_eq!(result.failed, 5);
    assert!(!result.compliant);
}
