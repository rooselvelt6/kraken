use supplychain::{
    CisScanner, GithubAdvisoryClient, LicenseChecker, NvdClient, OsvClient, PolicyEngine,
    SbomDiffer, SlsaVerifier, TyposquatDetector,
};
use supplychain::cis::{CheckResult, CisBenchmark, CisCheck};
use supplychain::github::{AdvisoryQueryResult, AdvisoryVuln, GithubAdvisory};
use supplychain::license::{LicenseAudit, LicenseCategory, LicenseEntry};
use supplychain::nvd::{CvssV3, LangString, NvdCve, NvdMetrics, NvdReference, NvdSearchResult,
                       NvdWeakness};
use supplychain::osv::{OsvAffected, OsvEvent, OsvPackage, OsvQuery, OsvRange, OsvResponse,
                       OsvSeverity, OsvVuln};
use supplychain::policy::{PolicyAction, PolicyConfig, PolicyEvalResult, PolicyRule, PolicyViolation};
use supplychain::sbom::{Sbom, SbomDiffResult, SbomPackage, SbomRelationship, VersionChange};
use supplychain::slsa::{SlsaBuilder, SlsaByproduct, SlsaCheck, SlsaConfigSource, SlsaInvocation,
                        SlsaLevel, SlsaMaterial, SlsaProvenance, SlsaVerificationResult};
use supplychain::typosquat::{TyposquatMatch, TyposquatResult};

// ─── LicenseChecker ─────────────────────────────────────────────────────────

#[test]
fn license_audit_all_permissive() {
    let deps = vec![("serde", "1.0", "MIT"), ("tokio", "1.0", "Apache-2.0")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.total_dependencies, 2);
    assert_eq!(audit.allowed.len(), 2);
    assert!(audit.restricted.is_empty());
    assert!(audit.unknown.is_empty());
}

#[test]
fn license_audit_restricted_detected() {
    let deps = vec![("a", "1.0", "MIT"), ("b", "2.0", "GPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.restricted.len(), 1);
    assert_eq!(audit.restricted[0].package, "b");
}

#[test]
fn license_audit_unknown_detected() {
    let deps = vec![("pkg", "1.0", "SomeWeirdLicense")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.unknown.len(), 1);
}

#[test]
fn license_audit_empty() {
    let audit = LicenseChecker::audit(&[]);
    assert_eq!(audit.total_dependencies, 0);
    assert_eq!(audit.compliance_pct, 100.0);
}

#[test]
fn license_audit_compliance_pct() {
    let deps = vec![
        ("a", "1.0", "MIT"),
        ("b", "1.0", "MIT"),
        ("c", "1.0", "GPL-3.0-only"),
    ];
    let audit = LicenseChecker::audit(&deps);
    assert!((audit.compliance_pct - 66.6).abs() < 1.0);
}

#[test]
fn license_audit_mpl_is_weak_protective() {
    let deps = vec![("pkg", "1.0", "MPL-2.0")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed[0].category, LicenseCategory::WeakProtective);
}

#[test]
fn license_audit_lgpl_is_weak_protective() {
    let deps = vec![("pkg", "1.0", "LGPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed[0].category, LicenseCategory::WeakProtective);
}

#[test]
fn license_audit_agpl_is_strong_protective() {
    let deps = vec![("pkg", "1.0", "AGPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed[0].category, LicenseCategory::StrongProtective);
}

#[test]
fn license_audit_proprietary_is_restricted() {
    let deps = vec![("pkg", "1.0", "Proprietary")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.restricted.len(), 1);
}

#[test]
fn license_audit_commercial_is_restricted() {
    let deps = vec![("pkg", "1.0", "Commercial")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.restricted.len(), 1);
}

#[test]
fn license_audit_empty_license_is_unknown() {
    let deps = vec![("pkg", "1.0", "")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.unknown.len(), 1);
}

#[test]
fn license_audit_uppercase_unknown() {
    let deps = vec![("pkg", "1.0", "UNKNOWN")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.unknown.len(), 1);
}

#[test]
fn license_audit_recommends_restricted() {
    let deps = vec![("pkg", "1.0", "GPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert!(audit.recommendations.iter().any(|r| r.contains("restricted")));
}

#[test]
fn license_audit_recommends_unknown() {
    let deps = vec![("pkg", "1.0", "WeirdLicense")];
    let audit = LicenseChecker::audit(&deps);
    assert!(audit
        .recommendations
        .iter()
        .any(|r| r.contains("unknown")));
}

#[test]
fn license_audit_always_recommends_compliance_pct() {
    let deps = vec![("pkg", "1.0", "MIT")];
    let audit = LicenseChecker::audit(&deps);
    assert!(audit
        .recommendations
        .iter()
        .any(|r| r.contains("100.0%")));
}

#[test]
fn license_entry_struct() {
    let e = LicenseEntry {
        package: "test".to_string(),
        version: "1.0".to_string(),
        license: "MIT".to_string(),
        category: LicenseCategory::Permissive,
    };
    assert_eq!(e.category, LicenseCategory::Permissive);
}

#[test]
fn license_checker_default() {
    let _ = LicenseChecker::default();
}

#[test]
fn license_audit_serde_roundtrip() {
    let audit = LicenseChecker::audit(&[("a", "1.0", "MIT")]);
    let json = serde_json::to_string(&audit).unwrap();
    let back: LicenseAudit = serde_json::from_str(&json).unwrap();
    assert_eq!(audit.total_dependencies, back.total_dependencies);
}

#[test]
fn license_category_variants() {
    assert_eq!(LicenseCategory::Permissive, LicenseCategory::Permissive);
    assert_eq!(LicenseCategory::WeakProtective, LicenseCategory::WeakProtective);
    assert_eq!(
        LicenseCategory::StrongProtective,
        LicenseCategory::StrongProtective
    );
    assert_eq!(LicenseCategory::Restricted, LicenseCategory::Restricted);
    assert_eq!(LicenseCategory::Unknown, LicenseCategory::Unknown);
    assert_ne!(LicenseCategory::Permissive, LicenseCategory::Restricted);
}

// ─── TyposquatDetector ──────────────────────────────────────────────────────

#[test]
fn typosquat_unique_package_low_risk() {
    let r = TyposquatDetector::check("zzz-unique-abc-123");
    assert_eq!(r.risk_level, "LOW");
    assert_eq!(r.total_suspicious, 0);
}

#[test]
fn typosquat_known_typo_high_risk() {
    let r = TyposquatDetector::check("reqwuest");
    assert!(r.total_suspicious > 0);
    assert_eq!(r.risk_level, "HIGH");
}

#[test]
fn typosquat_homograph_detected() {
    let r = TyposquatDetector::check("sеrde");
    let homographs = r
        .matches
        .iter()
        .filter(|m| m.technique == "homograph")
        .count();
    assert!(homographs > 0);
}

#[test]
fn typosquat_combosquatting_detected() {
    let r = TyposquatDetector::check("serde");
    let combos = r
        .matches
        .iter()
        .filter(|m| m.technique.contains("combosquatting"))
        .count();
    assert!(combos > 0);
}

#[test]
fn typosquat_long_name_no_combosquatting() {
    let r = TyposquatDetector::check("a-very-long-package-name-here");
    let combos = r
        .matches
        .iter()
        .filter(|m| m.technique.contains("combosquatting"))
        .count();
    assert_eq!(combos, 0);
}

#[test]
fn typosquat_prefix_suffix() {
    let r = TyposquatDetector::check("opensslabc");
    assert!(r.total_suspicious > 0);
}

#[test]
fn typosquat_serde_roundtrip() {
    let r = TyposquatDetector::check("test");
    let json = serde_json::to_string(&r).unwrap();
    let back: TyposquatResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.package, back.package);
}

#[test]
fn typosquat_result_struct_fields() {
    let r = TyposquatDetector::check("serde");
    assert_eq!(r.package, "serde");
    assert!(r.total_suspicious >= 0);
}

#[test]
fn typosquat_match_struct() {
    let m = TyposquatMatch {
        suspicious_name: "serde".to_string(),
        similarity: 0.9,
        technique: "typosquatting".to_string(),
        known_malicious: false,
    };
    assert_eq!(m.similarity, 0.9);
    assert!(!m.known_malicious);
}

#[test]
fn typosquat_match_known_malicious_true() {
    let m = TyposquatMatch {
        suspicious_name: "test".to_string(),
        similarity: 1.0,
        technique: "homograph".to_string(),
        known_malicious: true,
    };
    assert!(m.known_malicious);
}

#[test]
fn typosquat_detector_default() {
    let _ = TyposquatDetector::default();
}

#[test]
fn typosquat_risk_medium_or_high_for_serde_dev_test() {
    let r = TyposquatDetector::check("serde-dev-test");
    assert!(r.risk_level == "MEDIUM" || r.risk_level == "HIGH");
}

#[test]
fn typosquat_similarity_sorted_desc() {
    let r = TyposquatDetector::check("reqwuest");
    for window in r.matches.windows(2) {
        assert!(window[0].similarity >= window[1].similarity);
    }
}

#[test]
fn typosquat_no_duplicates_in_matches() {
    let r = TyposquatDetector::check("serde");
    let mut names: Vec<&str> = r.matches.iter().map(|m| m.suspicious_name.as_str()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), r.matches.len());
}

// ─── PolicyEngine ───────────────────────────────────────────────────────────

#[test]
fn policy_default_has_5_rules() {
    let p = PolicyEngine::default_policy();
    assert_eq!(p.rules.len(), 5);
    assert_eq!(p.name, "kraken-default");
    assert_eq!(p.version, "1.0");
}

#[test]
fn policy_evaluate_all_pass() {
    let p = PolicyEngine::default_policy();
    let findings = vec![
        ("SC-001", true),
        ("SC-002", true),
        ("SC-003", true),
        ("SC-004", true),
        ("SC-005", true),
    ];
    let r = PolicyEngine::evaluate(&p, &findings);
    assert!(r.compliant);
    assert_eq!(r.passed, 5);
    assert_eq!(r.failed, 0);
}

#[test]
fn policy_evaluate_deny_violation() {
    let p = PolicyEngine::default_policy();
    let findings = vec![
        ("SC-001", false),
        ("SC-002", true),
        ("SC-003", true),
        ("SC-004", true),
        ("SC-005", true),
    ];
    let r = PolicyEngine::evaluate(&p, &findings);
    assert!(!r.compliant);
    assert_eq!(r.failed, 1);
}

#[test]
fn policy_evaluate_warn_only_still_compliant() {
    let p = PolicyConfig {
        name: "warn-only".to_string(),
        version: "1.0".to_string(),
        severity: "low".to_string(),
        rules: vec![PolicyRule {
            id: "W1".to_string(),
            name: "warn".to_string(),
            c_type: "test".to_string(),
            condition: "test".to_string(),
            action: PolicyAction::Warn,
            severity: "low".to_string(),
        }],
    };
    let r = PolicyEngine::evaluate(&p, &[("W1", false)]);
    assert!(r.compliant);
    assert_eq!(r.failed, 1);
}

#[test]
fn policy_evaluate_empty_findings_all_fail() {
    let p = PolicyEngine::default_policy();
    let r = PolicyEngine::evaluate(&p, &[]);
    assert!(!r.compliant);
    assert_eq!(r.failed, 5);
}

#[test]
fn policy_evaluate_unknown_rule_id() {
    let p = PolicyEngine::default_policy();
    let r = PolicyEngine::evaluate(&p, &[("UNKNOWN", true)]);
    assert_eq!(r.failed, 5);
}

#[test]
fn policy_action_variants() {
    assert_eq!(PolicyAction::Allow, PolicyAction::Allow);
    assert_eq!(PolicyAction::Deny, PolicyAction::Deny);
    assert_eq!(PolicyAction::Warn, PolicyAction::Warn);
    assert_ne!(PolicyAction::Allow, PolicyAction::Deny);
    assert_ne!(PolicyAction::Allow, PolicyAction::Warn);
    assert_ne!(PolicyAction::Deny, PolicyAction::Warn);
}

#[test]
fn policy_violation_struct() {
    let v = PolicyViolation {
        rule_id: "R1".to_string(),
        rule_name: "Test".to_string(),
        message: "violated".to_string(),
        action: PolicyAction::Deny,
    };
    assert_eq!(v.action, PolicyAction::Deny);
}

#[test]
fn policy_eval_result_struct() {
    let r = PolicyEvalResult {
        policy: "test".to_string(),
        total_rules: 5,
        passed: 3,
        failed: 2,
        violations: vec![],
        compliant: true,
    };
    assert!(r.compliant);
    assert_eq!(r.total_rules, 5);
}

#[test]
fn policy_rule_struct() {
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
fn policy_serde_roundtrip() {
    let p = PolicyEngine::default_policy();
    let json = serde_json::to_string(&p).unwrap();
    let back: PolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(p.name, back.name);
    assert_eq!(p.rules.len(), back.rules.len());
}

#[test]
fn policy_eval_result_serde_roundtrip() {
    let p = PolicyEngine::default_policy();
    let r = PolicyEngine::evaluate(&p, &[]);
    let json = serde_json::to_string(&r).unwrap();
    let back: PolicyEvalResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.failed, back.failed);
}

#[test]
fn policy_engine_default() {
    let _ = PolicyEngine::default();
}

#[test]
fn policy_rule_ids_are_unique() {
    let p = PolicyEngine::default_policy();
    let mut ids: Vec<&str> = p.rules.iter().map(|r| r.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), p.rules.len());
}

// ─── CisScanner ─────────────────────────────────────────────────────────────

#[test]
fn cis_docker_scan_target() {
    let b = CisScanner::scan_docker("");
    assert_eq!(b.target, "Docker");
    assert!(b.total_checks > 0);
}

#[test]
fn cis_docker_scan_empty_fails_all() {
    let b = CisScanner::scan_docker("");
    assert!(b.failed > 0);
}

#[test]
fn cis_kubernetes_scan_readonly_rootfs() {
    let b = CisScanner::scan_kubernetes("readOnlyRootFilesystem: true");
    let k3 = b.checks.iter().find(|c| c.id == "K-3").unwrap();
    assert_eq!(k3.status, CheckResult::Pass);
}

#[test]
fn cis_kubernetes_scan_not_privileged() {
    let b = CisScanner::scan_kubernetes("privileged: false");
    let k2 = b.checks.iter().find(|c| c.id == "K-2").unwrap();
    assert_eq!(k2.status, CheckResult::Pass);
}

#[test]
fn cis_kubernetes_scan_privileged_fails() {
    let b = CisScanner::scan_kubernetes("privileged: true");
    let k2 = b.checks.iter().find(|c| c.id == "K-2").unwrap();
    assert_eq!(k2.status, CheckResult::Fail);
}

#[test]
fn cis_kubernetes_scan_automount_false() {
    let b = CisScanner::scan_kubernetes("automountserviceaccounttoken: false");
    let k4 = b.checks.iter().find(|c| c.id == "K-4").unwrap();
    assert_eq!(k4.status, CheckResult::Pass);
}

#[test]
fn cis_linux_scan_passing() {
    let sysctl = "kernel.randomize_va_space = 2\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.tcp_syncookies = 1";
    let b = CisScanner::scan_linux(sysctl);
    assert!(b.passed >= 3);
}

#[test]
fn cis_linux_scan_failing() {
    let b = CisScanner::scan_linux("");
    assert!(b.failed > 0);
}

#[test]
fn cis_compliance_pct_calculation() {
    let b = CisScanner::scan_docker("");
    assert!(b.compliance_pct >= 0.0);
    assert!(b.compliance_pct <= 100.0);
}

#[test]
fn cis_check_result_variants() {
    assert_eq!(CheckResult::Pass, CheckResult::Pass);
    assert_eq!(CheckResult::Fail, CheckResult::Fail);
    assert_eq!(CheckResult::Na, CheckResult::Na);
    assert_ne!(CheckResult::Pass, CheckResult::Fail);
    assert_ne!(CheckResult::Pass, CheckResult::Na);
    assert_ne!(CheckResult::Fail, CheckResult::Na);
}

#[test]
fn cis_check_has_remediation() {
    let b = CisScanner::scan_docker("");
    for check in &b.checks {
        assert!(!check.remediation.is_empty());
    }
}

#[test]
fn cis_check_has_description() {
    let b = CisScanner::scan_linux("kernel.randomize_va_space = 2");
    for check in &b.checks {
        assert!(!check.description.is_empty());
    }
}

#[test]
fn cis_benchmark_serde_roundtrip() {
    let b = CisScanner::scan_docker("");
    let json = serde_json::to_string(&b).unwrap();
    let back: CisBenchmark = serde_json::from_str(&json).unwrap();
    assert_eq!(b.target, back.target);
    assert_eq!(b.total_checks, back.total_checks);
}

#[test]
fn cis_scanner_default() {
    let _ = CisScanner::default();
}

// ─── SbomDiffer ─────────────────────────────────────────────────────────────

#[test]
fn sbom_diff_identical() {
    let sbom = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let r = SbomDiffer::diff(&sbom, &sbom);
    assert!(r.added_packages.is_empty());
    assert!(r.removed_packages.is_empty());
    assert!(r.changed_versions.is_empty());
}

#[test]
fn sbom_diff_added_package() {
    let a = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let mut b = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    b.packages.push(SbomPackage {
        name: "new".to_string(),
        version: "1.0".to_string(),
        supplier: None,
        licenses: vec![],
        checksum: None,
        purl: None,
    });
    let r = SbomDiffer::diff(&a, &b);
    assert_eq!(r.added_packages.len(), 1);
}

#[test]
fn sbom_diff_removed_package() {
    let a = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT"), ("b", "2.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let r = SbomDiffer::diff(&a, &b);
    assert_eq!(r.removed_packages.len(), 1);
    assert_eq!(r.removed_packages[0].name, "b");
}

#[test]
fn sbom_diff_version_change() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "2.0.0", "MIT")]);
    let r = SbomDiffer::diff(&a, &b);
    assert_eq!(r.changed_versions.len(), 1);
    assert!(r.changed_versions[0].major_change);
}

#[test]
fn sbom_diff_minor_version_change() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "1.1.0", "MIT")]);
    let r = SbomDiffer::diff(&a, &b);
    assert_eq!(r.changed_versions.len(), 1);
    assert!(!r.changed_versions[0].major_change);
}

#[test]
fn sbom_diff_no_changes_summary() {
    let a = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let r = SbomDiffer::diff(&a, &a);
    assert!(r.summary.contains("No changes"));
}

#[test]
fn sbom_diff_changes_summary() {
    let a = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let mut b = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    b.packages.push(SbomPackage {
        name: "new".to_string(),
        version: "1.0".to_string(),
        supplier: None,
        licenses: vec![],
        checksum: None,
        purl: None,
    });
    let r = SbomDiffer::diff(&a, &b);
    assert!(r.summary.contains("1 added"));
}

#[test]
fn sbom_generate_sbom_format() {
    let sbom = SbomDiffer::generate_sbom(&[]);
    assert_eq!(sbom.format, "SPDX-2.3");
}

#[test]
fn sbom_generate_sbom_packages() {
    let sbom = SbomDiffer::generate_sbom(&[
        ("a", "1.0", "MIT"),
        ("b", "2.0", "Apache-2.0"),
    ]);
    assert_eq!(sbom.packages.len(), 2);
    assert_eq!(sbom.relationships.len(), 1);
    assert!(sbom.packages[0].purl.is_some());
}

#[test]
fn sbom_generate_sbom_purl_format() {
    let sbom = SbomDiffer::generate_sbom(&[("my-pkg", "3.0", "MIT")]);
    assert_eq!(
        sbom.packages[0].purl.as_deref(),
        Some("pkg:cargo/my-pkg@3.0")
    );
}

#[test]
fn sbom_diff_multiple_added_and_removed() {
    let a = SbomDiffer::generate_sbom(&[("x", "1.0", "MIT"), ("y", "2.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("x", "1.0", "MIT"), ("z", "3.0", "MIT")]);
    let r = SbomDiffer::diff(&a, &b);
    assert_eq!(r.added_packages.len(), 1);
    assert_eq!(r.removed_packages.len(), 1);
    assert_eq!(r.added_packages[0].name, "z");
    assert_eq!(r.removed_packages[0].name, "y");
}

#[test]
fn sbom_differ_default() {
    let _ = SbomDiffer::default();
}

#[test]
fn sbom_serde_roundtrip() {
    let sbom = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let json = serde_json::to_string(&sbom).unwrap();
    let back: Sbom = serde_json::from_str(&json).unwrap();
    assert_eq!(sbom.packages.len(), back.packages.len());
}

#[test]
fn sbom_package_struct() {
    let p = SbomPackage {
        name: "test".to_string(),
        version: "1.0".to_string(),
        supplier: Some("TestCo".to_string()),
        licenses: vec!["MIT".to_string()],
        checksum: Some("sha256:abc".to_string()),
        purl: None,
    };
    assert_eq!(p.supplier, Some("TestCo".to_string()));
    assert!(p.checksum.is_some());
}

#[test]
fn sbom_relationship_struct() {
    let r = SbomRelationship {
        source: "app".to_string(),
        target: "lib".to_string(),
        rel_type: "DEPENDS_ON".to_string(),
    };
    assert_eq!(r.rel_type, "DEPENDS_ON");
}

#[test]
fn sbom_version_change_struct() {
    let vc = VersionChange {
        name: "pkg".to_string(),
        old_version: "1.0.0".to_string(),
        new_version: "2.0.0".to_string(),
        major_change: true,
    };
    assert!(vc.major_change);
}

#[test]
fn sbom_diff_serde_roundtrip() {
    let a = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let r = SbomDiffer::diff(&a, &a);
    let json = serde_json::to_string(&r).unwrap();
    let back: SbomDiffResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.added_packages.len(), back.added_packages.len());
}

// ─── SlsaVerifier ───────────────────────────────────────────────────────────

#[test]
fn slsa_verify_l3() {
    let prov = SlsaVerifier::generate_provenance(
        "https://github.com/example/builder",
        "https://github.com/example/repo",
        &[("src.tar.gz", "sha256:abc123")],
    );
    let r = SlsaVerifier::verify(&prov, SlsaLevel::L3);
    assert!(r.proven);
    assert_eq!(r.level, SlsaLevel::L3);
}

#[test]
fn slsa_verify_none() {
    let prov = SlsaProvenance {
        builder: SlsaBuilder {
            id: String::new(),
        },
        build_type: String::new(),
        invocation: SlsaInvocation {
            config_source: SlsaConfigSource {
                uri: String::new(),
                digest: None,
                entry_point: String::new(),
            },
            parameters: vec![],
        },
        materials: vec![],
        byproducts: vec![],
    };
    let r = SlsaVerifier::verify(&prov, SlsaLevel::L1);
    assert!(!r.proven);
    assert_eq!(r.level, SlsaLevel::None);
}

#[test]
fn slsa_verify_l2() {
    let prov = SlsaVerifier::generate_provenance(
        "builder-id",
        "https://github.com/example/repo",
        &[("src.tar.gz", "sha256:abc")],
    );
    let r = SlsaVerifier::verify(&prov, SlsaLevel::L2);
    assert!(r.proven);
}

#[test]
fn slsa_verify_l4_not_met() {
    let prov = SlsaVerifier::generate_provenance(
        "builder",
        "https://repo.example.com/build",
        &[("src.tar.gz", "sha256:abc")],
    );
    let r = SlsaVerifier::verify(&prov, SlsaLevel::L4);
    assert!(!r.proven);
}

#[test]
fn slsa_level_ordering() {
    assert!(SlsaLevel::None < SlsaLevel::L1);
    assert!(SlsaLevel::L1 < SlsaLevel::L2);
    assert!(SlsaLevel::L2 < SlsaLevel::L3);
    assert!(SlsaLevel::L3 < SlsaLevel::L4);
}

#[test]
fn slsa_level_equality() {
    assert_eq!(SlsaLevel::L1, SlsaLevel::L1);
    assert_ne!(SlsaLevel::L1, SlsaLevel::L2);
}

#[test]
fn slsa_generate_provenance_materials() {
    let prov = SlsaVerifier::generate_provenance(
        "b",
        "r",
        &[("a.tar.gz", "sha256:aaa"), ("b.tar.gz", "sha256:bbb")],
    );
    assert_eq!(prov.materials.len(), 2);
    assert_eq!(prov.materials[0].uri, "a.tar.gz");
}

#[test]
fn slsa_generate_provenance_has_byproducts() {
    let prov = SlsaVerifier::generate_provenance("b", "r", &[]);
    assert_eq!(prov.byproducts.len(), 1);
    assert_eq!(prov.byproducts[0].name, "sha256");
}

#[test]
fn slsa_checks_count_by_target_level() {
    let prov = SlsaVerifier::generate_provenance(
        "b",
        "https://repo.example.com",
        &[("s.tar.gz", "sha256:abc")],
    );
    let r_l1 = SlsaVerifier::verify(&prov, SlsaLevel::L1);
    let r_l2 = SlsaVerifier::verify(&prov, SlsaLevel::L2);
    let r_l3 = SlsaVerifier::verify(&prov, SlsaLevel::L3);
    assert!(r_l2.checks.len() > r_l1.checks.len());
    assert!(r_l3.checks.len() >= r_l2.checks.len());
}

#[test]
fn slsa_verification_result_serde_roundtrip() {
    let prov = SlsaVerifier::generate_provenance("b", "r", &[]);
    let r = SlsaVerifier::verify(&prov, SlsaLevel::L1);
    let json = serde_json::to_string(&r).unwrap();
    let back: SlsaVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.proven, back.proven);
}

#[test]
fn slsa_provenance_serde_roundtrip() {
    let prov = SlsaVerifier::generate_provenance(
        "https://builder.example.com",
        "https://repo.example.com",
        &[("src.tar.gz", "sha256:abc123")],
    );
    let json = serde_json::to_string(&prov).unwrap();
    let back: SlsaProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(prov.builder.id, back.builder.id);
}

#[test]
fn slsa_verifier_default() {
    let _ = SlsaVerifier::default();
}

#[test]
fn slsa_check_struct() {
    let c = SlsaCheck {
        name: "test".to_string(),
        passed: true,
        description: "desc".to_string(),
    };
    assert!(c.passed);
}

#[test]
fn slsa_verify_l1_only_needs_builder() {
    let prov = SlsaVerifier::generate_provenance("builder-id", "", &[]);
    let r = SlsaVerifier::verify(&prov, SlsaLevel::L1);
    assert!(r.proven);
}

#[test]
fn slsa_verify_empty_builder_no_level() {
    let prov = SlsaProvenance {
        builder: SlsaBuilder {
            id: String::new(),
        },
        build_type: String::new(),
        invocation: SlsaInvocation {
            config_source: SlsaConfigSource {
                uri: String::new(),
                digest: None,
                entry_point: String::new(),
            },
            parameters: vec![],
        },
        materials: vec![],
        byproducts: vec![],
    };
    let r = SlsaVerifier::verify(&prov, SlsaLevel::None);
    assert!(r.proven);
}

#[test]
fn slsa_level_variants() {
    assert_eq!(format!("{:?}", SlsaLevel::None), "None");
    assert_eq!(format!("{:?}", SlsaLevel::L1), "L1");
    assert_eq!(format!("{:?}", SlsaLevel::L2), "L2");
    assert_eq!(format!("{:?}", SlsaLevel::L3), "L3");
    assert_eq!(format!("{:?}", SlsaLevel::L4), "L4");
}

// ─── OsvClient ──────────────────────────────────────────────────────────────

#[test]
fn osv_query_openssl_with_version() {
    let r = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
    assert!(!r.vulns.is_empty());
}

#[test]
fn osv_query_openssl_without_version() {
    let r = OsvClient::query("openssl", "crates.io", None);
    assert!(!r.vulns.is_empty());
}

#[test]
fn osv_query_no_match() {
    let r = OsvClient::query("nonexistent", "crates.io", None);
    assert!(r.vulns.is_empty());
}

#[test]
fn osv_query_fixed_version_no_match() {
    let r = OsvClient::query("openssl", "crates.io", Some("1.0.5"));
    assert!(r.vulns.is_empty());
}

#[test]
fn osv_query_ecosystem_mismatch() {
    let r = OsvClient::query("openssl", "npm", Some("1.0.2"));
    assert!(r.vulns.is_empty());
}

#[test]
fn osv_query_log4j() {
    let r = OsvClient::query("log4j", "Maven", Some("2.14.0"));
    assert!(!r.vulns.is_empty());
}

#[test]
fn osv_query_preserves_version() {
    let r = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
    assert_eq!(r.query.version, Some("1.0.2".to_string()));
}

#[test]
fn osv_query_preserves_package_name() {
    let r = OsvClient::query("openssl", "crates.io", None);
    assert_eq!(r.query.package.name, "openssl");
    assert_eq!(r.query.package.ecosystem, "crates.io");
}

#[test]
fn osv_client_default() {
    let _ = OsvClient::default();
}

#[test]
fn osv_vuln_struct() {
    let v = OsvVuln {
        id: "TEST-001".to_string(),
        summary: "test".to_string(),
        severity: vec![OsvSeverity {
            c_type: "CVSS_V3".to_string(),
            score: "5.0".to_string(),
        }],
        affected: vec![],
        references: vec![],
        published: "2024-01-01".to_string(),
        modified: "2024-06-01".to_string(),
    };
    assert_eq!(v.id, "TEST-001");
    assert_eq!(v.severity.len(), 1);
}

#[test]
fn osv_query_struct() {
    let q = OsvQuery {
        package: OsvPackage {
            name: "test".to_string(),
            ecosystem: "crates.io".to_string(),
            purl: Some("pkg:cargo/test@1.0".to_string()),
        },
        version: Some("1.0.0".to_string()),
    };
    assert_eq!(q.package.name, "test");
    assert!(q.version.is_some());
}

#[test]
fn osv_severity_struct() {
    let s = OsvSeverity {
        c_type: "CVSS_V3".to_string(),
        score: "9.8".to_string(),
    };
    assert_eq!(s.score, "9.8");
}

#[test]
fn osv_affected_struct() {
    let a = OsvAffected {
        package: OsvPackage {
            name: "test".to_string(),
            ecosystem: "crates.io".to_string(),
            purl: None,
        },
        ranges: vec![OsvRange {
            c_type: "SEMVER".to_string(),
            events: vec![OsvEvent {
                introduced: Some("1.0.0".to_string()),
                fixed: Some("2.0.0".to_string()),
            }],
        }],
        versions: vec!["1.0.0".to_string()],
    };
    assert_eq!(a.versions.len(), 1);
}

#[test]
fn osv_response_serde_roundtrip() {
    let r = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
    let json = serde_json::to_string(&r).unwrap();
    let back: OsvResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(r.vulns.len(), back.vulns.len());
}

// ─── GithubAdvisoryClient ───────────────────────────────────────────────────

#[test]
fn github_query_openssl() {
    let r = GithubAdvisoryClient::query("openssl", "crates.io");
    assert!(r.total_count > 0);
}

#[test]
fn github_query_npm() {
    let r = GithubAdvisoryClient::query("left-pad", "npm");
    assert!(r.total_count > 0);
}

#[test]
fn github_query_empty() {
    let r = GithubAdvisoryClient::query("unknown-pkg", "unknown-ecosystem");
    assert_eq!(r.total_count, 0);
}

#[test]
fn github_search_by_ghsa_id() {
    let a = GithubAdvisoryClient::search_by_ghsa_id("GHSA-xxxx-xxxx-xxxx");
    assert!(a.is_some());
}

#[test]
fn github_search_by_ghsa_id_not_found() {
    let a = GithubAdvisoryClient::search_by_ghsa_id("GHSA-nonexistent");
    assert!(a.is_none());
}

#[test]
fn github_advisory_client_default() {
    let _ = GithubAdvisoryClient::default();
}

#[test]
fn github_advisory_struct() {
    let a = GithubAdvisory {
        ghsa_id: "GHSA-123".to_string(),
        cve_id: Some("CVE-2024-1234".to_string()),
        summary: "test".to_string(),
        description: "desc".to_string(),
        severity: "HIGH".to_string(),
        cvss_score: Some(7.5),
        published_at: "2024-01-01".to_string(),
        updated_at: "2024-06-01".to_string(),
        vulnerabilities: vec![],
        references: vec![],
        credits: vec![],
    };
    assert_eq!(a.severity, "HIGH");
}

#[test]
fn github_advisory_vuln_struct() {
    let v = AdvisoryVuln {
        package: "pkg".to_string(),
        ecosystem: "npm".to_string(),
        vulnerable_version_range: "< 2.0.0".to_string(),
        first_patched_version: Some("2.0.0".to_string()),
    };
    assert!(v.first_patched_version.is_some());
}

#[test]
fn github_query_result_serde_roundtrip() {
    let r = GithubAdvisoryClient::query("openssl", "crates.io");
    let json = serde_json::to_string(&r).unwrap();
    let back: AdvisoryQueryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.total_count, back.total_count);
}

#[test]
fn github_query_result_query_field() {
    let r = GithubAdvisoryClient::query("my-pkg", "npm");
    assert_eq!(r.query, "my-pkg (npm)");
}

// ─── NvdClient ──────────────────────────────────────────────────────────────

#[test]
fn nvd_search_openssl() {
    let r = NvdClient::search_cve("openssl");
    assert!(r.total_results > 0);
}

#[test]
fn nvd_search_by_cve_id() {
    let c = NvdClient::search_by_cve_id("CVE-2024-0001");
    assert!(c.is_some());
}

#[test]
fn nvd_search_nonexistent() {
    let r = NvdClient::search_cve("nonexistent-vuln-xyz");
    assert_eq!(r.total_results, 0);
}

#[test]
fn nvd_cvss_fields() {
    let cve = NvdClient::search_by_cve_id("CVE-2024-0001").unwrap();
    let cvss = cve.metrics.unwrap().cvss_v3.unwrap();
    assert_eq!(cvss.base_score, 9.8);
    assert_eq!(cvss.base_severity, "CRITICAL");
}

#[test]
fn nvd_client_default() {
    let _ = NvdClient::default();
}

#[test]
fn nvd_severity_color() {
    assert_eq!(NvdClient::severity_color("CRITICAL"), "\x1b[31m");
    assert_eq!(NvdClient::severity_color("HIGH"), "\x1b[33m");
    assert_eq!(NvdClient::severity_color("MEDIUM"), "\x1b[33m");
    assert_eq!(NvdClient::severity_color("LOW"), "\x1b[32m");
    assert_eq!(NvdClient::severity_color("UNKNOWN"), "\x1b[0m");
}

#[test]
fn nvd_cve_struct() {
    let cve = NvdCve {
        id: "CVE-2024-9999".to_string(),
        source_identifier: "test".to_string(),
        published: "2024-01-01T00:00:00Z".to_string(),
        last_modified: "2024-06-01T00:00:00Z".to_string(),
        descriptions: vec![LangString {
            lang: "en".to_string(),
            value: "test vuln".to_string(),
        }],
        metrics: None,
        weaknesses: vec![],
        references: vec![],
    };
    assert_eq!(cve.id, "CVE-2024-9999");
}

#[test]
fn nvd_search_result_struct() {
    let r = NvdSearchResult {
        total_results: 5,
        results_per_page: 20,
        vulnerabilities: vec![],
        query: "test".to_string(),
    };
    assert_eq!(r.total_results, 5);
}

#[test]
fn nvd_cvss_v3_struct() {
    let v = CvssV3 {
        version: "3.1".to_string(),
        vector_string: "CVSS:3.1/AV:N/AC:L".to_string(),
        base_score: 9.8,
        base_severity: "CRITICAL".to_string(),
        attack_vector: "Network".to_string(),
        attack_complexity: "Low".to_string(),
        privileges_required: "None".to_string(),
        user_interaction: "None".to_string(),
        scope: "Unchanged".to_string(),
        confidentiality: "High".to_string(),
        integrity: "High".to_string(),
        availability: "High".to_string(),
    };
    assert_eq!(v.base_score, 9.8);
}

#[test]
fn nvd_weakness_struct() {
    let w = NvdWeakness {
        c_type: " CWE-120 ".to_string(),
        description: vec![LangString {
            lang: "en".to_string(),
            value: "Buffer Copy".to_string(),
        }],
    };
    assert_eq!(w.description.len(), 1);
}

#[test]
fn nvd_reference_struct() {
    let r = NvdReference {
        url: "https://example.com".to_string(),
        tags: vec!["Patch".to_string()],
    };
    assert_eq!(r.tags.len(), 1);
}

#[test]
fn nvd_result_serde_roundtrip() {
    let r = NvdClient::search_cve("openssl");
    let json = serde_json::to_string(&r).unwrap();
    let back: NvdSearchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.total_results, back.total_results);
}
