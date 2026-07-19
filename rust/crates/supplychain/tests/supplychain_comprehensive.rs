use supplychain::{
    CisScanner, GithubAdvisoryClient, LicenseChecker, NvdClient, OsvClient, PolicyEngine,
    SbomDiffer, SlsaVerifier, TyposquatDetector,
};
use supplychain::license::{LicenseAudit, LicenseCategory, LicenseEntry};
use supplychain::policy::{PolicyAction, PolicyConfig, PolicyEvalResult, PolicyRule, PolicyViolation};
use supplychain::typosquat::{TyposquatMatch, TyposquatResult};
use supplychain::osv::{
    OsvAffected, OsvEvent, OsvPackage, OsvQuery, OsvRange, OsvResponse,
    OsvSeverity, OsvVuln,
};
use supplychain::github::{
    AdvisoryQueryResult, AdvisoryVuln, GithubAdvisory,
};
use supplychain::nvd::{
    CvssV2, CvssV3, LangString, NvdCve, NvdMetrics, NvdReference,
    NvdSearchResult, NvdWeakness,
};
use supplychain::cis::{CheckResult, CisBenchmark};
use supplychain::sbom::{Sbom, SbomDiffResult, SbomPackage, SbomRelationship, VersionChange};
use supplychain::slsa::{
    SlsaBuilder, SlsaCheck, SlsaConfigSource, SlsaInvocation, SlsaLevel,
    SlsaProvenance, SlsaVerificationResult,
};

#[test]
fn license_checker_new() {
    let _checker = LicenseChecker::new();
}

#[test]
fn license_checker_default() {
    let _checker = LicenseChecker;
}

#[test]
fn license_audit_empty() {
    let audit = LicenseChecker::audit(&[]);
    assert_eq!(audit.total_dependencies, 0);
    assert_eq!(audit.compliance_pct, 100.0);
    assert!(audit.restricted.is_empty());
    assert!(audit.unknown.is_empty());
}

#[test]
fn license_audit_all_permissive() {
    let deps = vec![("serde", "1.0", "MIT"), ("reqwest", "0.11", "Apache-2.0")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.total_dependencies, 2);
    assert_eq!(audit.allowed.len(), 2);
    assert!(audit.restricted.is_empty());
    assert_eq!(audit.compliance_pct, 100.0);
}

#[test]
fn license_audit_restricted_gpl() {
    let deps = vec![("pkg", "1.0", "GPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.restricted.len(), 1);
    assert_eq!(audit.allowed.len(), 0);
    assert_eq!(audit.compliance_pct, 0.0);
}

#[test]
fn license_audit_unknown() {
    let deps = vec![("pkg", "1.0", "SomeWeirdLicense")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.unknown.len(), 1);
    assert_eq!(audit.allowed.len(), 0);
}

#[test]
fn license_audit_empty_string() {
    let deps = vec![("pkg", "1.0", "")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.unknown.len(), 1);
}

#[test]
fn license_audit_mixed() {
    let deps = vec![
        ("a", "1.0", "MIT"),
        ("b", "2.0", "GPL-3.0-only"),
        ("c", "3.0", "Apache-2.0"),
    ];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.total_dependencies, 3);
    assert_eq!(audit.allowed.len(), 2);
    assert_eq!(audit.restricted.len(), 1);
}

#[test]
fn license_category_mpl() {
    let deps = vec![("pkg", "1.0", "MPL-2.0")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed[0].category, LicenseCategory::WeakProtective);
}

#[test]
fn license_category_lgpl() {
    let deps = vec![("pkg", "1.0", "LGPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed[0].category, LicenseCategory::WeakProtective);
}

#[test]
fn license_category_agpl() {
    let deps = vec![("pkg", "1.0", "AGPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed[0].category, LicenseCategory::StrongProtective);
}

#[test]
fn license_category_proprietary() {
    let deps = vec![("pkg", "1.0", "Proprietary")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.restricted.len(), 1);
}

#[test]
fn license_category_commercial() {
    let deps = vec![("pkg", "1.0", "Commercial")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.restricted.len(), 1);
}

#[test]
fn license_audit_serde_roundtrip() {
    let deps = vec![("test", "1.0", "MIT")];
    let audit = LicenseChecker::audit(&deps);
    let json = serde_json::to_string(&audit).unwrap();
    let deserialized: LicenseAudit = serde_json::from_str(&json).unwrap();
    assert_eq!(audit.total_dependencies, deserialized.total_dependencies);
    assert_eq!(audit.compliance_pct, deserialized.compliance_pct);
}

#[test]
fn license_entry_serde_roundtrip() {
    let entry = LicenseEntry {
        package: "pkg".to_string(),
        version: "1.0".to_string(),
        license: "MIT".to_string(),
        category: LicenseCategory::Permissive,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: LicenseEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry.package, deserialized.package);
    assert_eq!(entry.category, deserialized.category);
}

#[test]
fn license_category_serde_roundtrip() {
    let categories = vec![
        LicenseCategory::Permissive,
        LicenseCategory::WeakProtective,
        LicenseCategory::StrongProtective,
        LicenseCategory::Restricted,
        LicenseCategory::Unknown,
    ];
    for cat in categories {
        let json = serde_json::to_string(&cat).unwrap();
        let deserialized: LicenseCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, deserialized);
    }
}

#[test]
fn license_audit_recommendations_compliance() {
    let deps = vec![("pkg", "1.0", "MIT")];
    let audit = LicenseChecker::audit(&deps);
    assert!(audit.recommendations.iter().any(|r| r.contains("100.0%")));
}

#[test]
fn license_audit_recommendations_restricted() {
    let deps = vec![("pkg", "1.0", "GPL-3.0-only")];
    let audit = LicenseChecker::audit(&deps);
    assert!(audit
        .recommendations
        .iter()
        .any(|r| r.contains("restricted")));
}

#[test]
fn license_audit_recommendations_unknown() {
    let deps = vec![("pkg", "1.0", "SomeWeirdLicense")];
    let audit = LicenseChecker::audit(&deps);
    assert!(audit.recommendations.iter().any(|r| r.contains("unknown")));
}

#[test]
fn license_audit_compliance_calculation() {
    let deps = vec![
        ("a", "1.0", "MIT"),
        ("b", "1.0", "MIT"),
        ("c", "1.0", "GPL-3.0-only"),
    ];
    let audit = LicenseChecker::audit(&deps);
    assert!((audit.compliance_pct - 66.6).abs() < 1.0);
}

#[test]
fn typosquat_detector_new() {
    let _det = TyposquatDetector::new();
}

#[test]
fn typosquat_detector_default() {
    let _det = TyposquatDetector;
}

#[test]
fn typosquat_check_unique() {
    let result = TyposquatDetector::check("zzz-unique-abc-123");
    assert_eq!(result.risk_level, "LOW");
    assert_eq!(result.total_suspicious, 0);
}

#[test]
fn typosquat_check_reqwest_typo() {
    let result = TyposquatDetector::check("reqwuest");
    assert!(result.total_suspicious > 0);
    assert_eq!(result.risk_level, "HIGH");
}

#[test]
fn typosquat_check_serde_combosquatting() {
    let result = TyposquatDetector::check("serde");
    let combos = result
        .matches
        .iter()
        .filter(|m| m.technique.contains("combosquatting"))
        .count();
    assert!(combos > 0);
}

#[test]
fn typosquat_check_homograph() {
    let result = TyposquatDetector::check("s\u{435}rde");
    let homographs = result
        .matches
        .iter()
        .filter(|m| m.technique == "homograph")
        .count();
    assert!(homographs > 0);
}

#[test]
fn typosquat_check_long_name_no_combosquatting() {
    let result = TyposquatDetector::check("a-very-long-package-name-here");
    let combos = result
        .matches
        .iter()
        .filter(|m| m.technique.contains("combosquatting"))
        .count();
    assert_eq!(combos, 0);
}

#[test]
fn typosquat_check_prefix_suffix() {
    let result = TyposquatDetector::check("opensslabc");
    let matches = result
        .matches
        .iter()
        .filter(|m| {
            m.technique.contains("dependency confusion") || m.technique.contains("typosquatting")
        })
        .count();
    assert!(matches > 0);
}

#[test]
fn typosquat_result_serde_roundtrip() {
    let result = TyposquatDetector::check("test");
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: TyposquatResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.package, deserialized.package);
    assert_eq!(result.risk_level, deserialized.risk_level);
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
fn typosquat_match_serde_roundtrip() {
    let m = TyposquatMatch {
        suspicious_name: "test".to_string(),
        similarity: 0.85,
        technique: "homograph".to_string(),
        known_malicious: true,
    };
    let json = serde_json::to_string(&m).unwrap();
    let deserialized: TyposquatMatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m.suspicious_name, deserialized.suspicious_name);
    assert_eq!(m.known_malicious, deserialized.known_malicious);
}

#[test]
fn typosquat_risk_medium() {
    let result = TyposquatDetector::check("serde-dev-test");
    assert!(result.risk_level == "MEDIUM" || result.risk_level == "HIGH");
}

#[test]
fn policy_engine_new() {
    let _engine = PolicyEngine::new();
}

#[test]
fn policy_engine_default() {
    let _engine = PolicyEngine;
}

#[test]
fn default_policy_has_5_rules() {
    let policy = PolicyEngine::default_policy();
    assert_eq!(policy.rules.len(), 5);
    assert_eq!(policy.name, "kraken-default");
    assert_eq!(policy.version, "1.0");
}

#[test]
fn evaluate_all_pass() {
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
    assert_eq!(result.failed, 0);
}

#[test]
fn evaluate_with_violation() {
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
fn evaluate_empty_findings() {
    let policy = PolicyEngine::default_policy();
    let result = PolicyEngine::evaluate(&policy, &[]);
    assert!(!result.compliant);
    assert_eq!(result.failed, 5);
}

#[test]
fn evaluate_partial_pass() {
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
fn evaluate_warn_only_violations_compliant() {
    let policy = PolicyConfig {
        name: "test".to_string(),
        version: "1.0".to_string(),
        severity: "low".to_string(),
        rules: vec![PolicyRule {
            id: "W1".to_string(),
            name: "Warn only".to_string(),
            c_type: "test".to_string(),
            condition: "test".to_string(),
            action: PolicyAction::Warn,
            severity: "low".to_string(),
        }],
    };
    let findings = vec![("W1", false)];
    let result = PolicyEngine::evaluate(&policy, &findings);
    assert!(result.compliant);
    assert_eq!(result.failed, 1);
}

#[test]
fn policy_eval_result_serde_roundtrip() {
    let policy = PolicyEngine::default_policy();
    let result = PolicyEngine::evaluate(&policy, &[]);
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: PolicyEvalResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.policy, deserialized.policy);
    assert_eq!(result.passed, deserialized.passed);
    assert_eq!(result.failed, deserialized.failed);
}

#[test]
fn policy_config_serde_roundtrip() {
    let policy = PolicyEngine::default_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: PolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(policy.name, deserialized.name);
    assert_eq!(policy.rules.len(), deserialized.rules.len());
}

#[test]
fn policy_action_variants_serde() {
    let actions = vec![PolicyAction::Allow, PolicyAction::Deny, PolicyAction::Warn];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: PolicyAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }
}

#[test]
fn policy_action_not_equal() {
    assert_ne!(PolicyAction::Allow, PolicyAction::Deny);
    assert_ne!(PolicyAction::Allow, PolicyAction::Warn);
    assert_ne!(PolicyAction::Deny, PolicyAction::Warn);
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
fn policy_violation_struct() {
    let v = PolicyViolation {
        rule_id: "R1".to_string(),
        rule_name: "Rule 1".to_string(),
        message: "violation".to_string(),
        action: PolicyAction::Deny,
    };
    assert_eq!(v.action, PolicyAction::Deny);
}

#[test]
fn evaluate_unknown_rule_id() {
    let policy = PolicyEngine::default_policy();
    let findings = vec![("UNKNOWN-ID", true)];
    let result = PolicyEngine::evaluate(&policy, &findings);
    assert_eq!(result.failed, 5);
}

#[test]
fn osv_client_new() {
    let _client = OsvClient::new();
}

#[test]
fn osv_client_default() {
    let _client = OsvClient;
}

#[test]
fn osv_query_with_version() {
    let resp = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
    assert!(!resp.vulns.is_empty());
}

#[test]
fn osv_query_without_version() {
    let resp = OsvClient::query("openssl", "crates.io", None);
    assert!(!resp.vulns.is_empty());
}

#[test]
fn osv_query_no_match() {
    let resp = OsvClient::query("nonexistent", "crates.io", None);
    assert!(resp.vulns.is_empty());
}

#[test]
fn osv_query_log4j() {
    let resp = OsvClient::query("log4j", "Maven", Some("2.14.0"));
    assert!(!resp.vulns.is_empty());
}

#[test]
fn osv_query_fixed_version() {
    let resp = OsvClient::query("openssl", "crates.io", Some("1.0.5"));
    assert!(resp.vulns.is_empty());
}

#[test]
fn osv_query_ecosystem_mismatch() {
    let resp = OsvClient::query("openssl", "npm", Some("1.0.2"));
    assert!(resp.vulns.is_empty());
}

#[test]
fn osv_response_serde_roundtrip() {
    let resp = OsvClient::query("test", "crates.io", None);
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: OsvResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp.vulns.len(), deserialized.vulns.len());
}

#[test]
fn osv_vuln_struct() {
    let vuln = OsvVuln {
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
    assert_eq!(vuln.id, "TEST-001");
}

#[test]
fn osv_query_struct() {
    let query = OsvQuery {
        package: OsvPackage {
            name: "test".to_string(),
            ecosystem: "crates.io".to_string(),
            purl: Some("pkg:cargo/test@1.0".to_string()),
        },
        version: Some("1.0.0".to_string()),
    };
    assert_eq!(query.package.name, "test");
}

#[test]
fn osv_query_preserves_version() {
    let resp = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
    assert_eq!(resp.query.version, Some("1.0.2".to_string()));
}

#[test]
fn github_advisory_client_new() {
    let _client = GithubAdvisoryClient::new();
}

#[test]
fn github_advisory_client_default() {
    let _client = GithubAdvisoryClient;
}

#[test]
fn github_query_openssl() {
    let result = GithubAdvisoryClient::query("openssl", "crates.io");
    assert!(result.total_count > 0);
}

#[test]
fn github_query_npm() {
    let result = GithubAdvisoryClient::query("left-pad", "npm");
    assert!(result.total_count > 0);
}

#[test]
fn github_query_empty() {
    let result = GithubAdvisoryClient::query("unknown-pkg", "unknown-ecosystem");
    assert_eq!(result.total_count, 0);
}

#[test]
fn github_search_by_id() {
    let advisory = GithubAdvisoryClient::search_by_ghsa_id("GHSA-xxxx-xxxx-xxxx");
    assert!(advisory.is_some());
}

#[test]
fn github_advisory_result_serde() {
    let result = GithubAdvisoryClient::query("test", "crates.io");
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: AdvisoryQueryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.total_count, deserialized.total_count);
}

#[test]
fn github_advisory_struct() {
    let adv = GithubAdvisory {
        ghsa_id: "GHSA-0000".to_string(),
        cve_id: Some("CVE-2024-0001".to_string()),
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
    assert_eq!(adv.severity, "HIGH");
}

#[test]
fn nvd_client_new() {
    let _client = NvdClient::new();
}

#[test]
fn nvd_client_default() {
    let _client = NvdClient;
}

#[test]
fn nvd_search_openssl() {
    let result = NvdClient::search_cve("openssl");
    assert!(result.total_results > 0);
}

#[test]
fn nvd_search_by_cve_id() {
    let cve = NvdClient::search_by_cve_id("CVE-2024-0001");
    assert!(cve.is_some());
}

#[test]
fn nvd_search_nonexistent() {
    let result = NvdClient::search_cve("nonexistent-xyz");
    assert_eq!(result.total_results, 0);
}

#[test]
fn nvd_cvss_fields() {
    let cve = NvdClient::search_by_cve_id("CVE-2024-0001").unwrap();
    let cvss = cve.metrics.unwrap().cvss_v3.unwrap();
    assert_eq!(cvss.base_score, 9.8);
}

#[test]
fn nvd_result_serde() {
    let result = NvdClient::search_cve("test");
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: NvdSearchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.total_results, deserialized.total_results);
}

#[test]
fn nvd_severity_color() {
    assert_eq!(NvdClient::severity_color("CRITICAL"), "\x1b[31m");
    assert_eq!(NvdClient::severity_color("HIGH"), "\x1b[33m");
    assert_eq!(NvdClient::severity_color("LOW"), "\x1b[32m");
}

#[test]
fn nvd_cve_struct() {
    let cve = NvdCve {
        id: "CVE-TEST".to_string(),
        source_identifier: "test@nist.gov".to_string(),
        published: "2024-01-01T00:00:00Z".to_string(),
        last_modified: "2024-06-01T00:00:00Z".to_string(),
        descriptions: vec![LangString {
            lang: "en".to_string(),
            value: "test".to_string(),
        }],
        metrics: None,
        weaknesses: vec![],
        references: vec![],
    };
    assert_eq!(cve.id, "CVE-TEST");
}

#[test]
fn cis_scanner_new() {
    let _scanner = CisScanner::new();
}

#[test]
fn cis_scanner_default() {
    let _scanner = CisScanner;
}

#[test]
fn cis_docker_scan() {
    let result = CisScanner::scan_docker("");
    assert_eq!(result.target, "Docker");
    assert!(result.total_checks > 0);
}

#[test]
fn cis_kubernetes_scan() {
    let result = CisScanner::scan_kubernetes("readOnlyRootFilesystem: true");
    assert!(result
        .checks
        .iter()
        .any(|c| c.id == "K-3" && c.status == CheckResult::Pass));
}

#[test]
fn cis_linux_scan_passing() {
    let sysctl =
        "kernel.randomize_va_space = 2\nnet.ipv4.conf.all.rp_filter = 1";
    let result = CisScanner::scan_linux(sysctl);
    assert!(result.passed >= 2);
}

#[test]
fn cis_linux_scan_failing() {
    let result = CisScanner::scan_linux("");
    assert!(result.failed > 0);
}

#[test]
fn cis_benchmark_serde() {
    let result = CisScanner::scan_docker("test");
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: CisBenchmark = serde_json::from_str(&json).unwrap();
    assert_eq!(result.target, deserialized.target);
    assert_eq!(result.total_checks, deserialized.total_checks);
}

#[test]
fn cis_check_result_serde() {
    let variants = vec![CheckResult::Pass, CheckResult::Fail, CheckResult::Na];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let deserialized: CheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, deserialized);
    }
}

#[test]
fn cis_check_result_not_equal() {
    assert_ne!(CheckResult::Pass, CheckResult::Fail);
    assert_ne!(CheckResult::Pass, CheckResult::Na);
    assert_ne!(CheckResult::Fail, CheckResult::Na);
}

#[test]
fn sbom_differ_new() {
    let _differ = SbomDiffer::new();
}

#[test]
fn sbom_differ_default() {
    let _differ = SbomDiffer;
}

#[test]
fn sbom_generate() {
    let sbom = SbomDiffer::generate_sbom(&[
        ("app", "1.0.0", "MIT"),
        ("serde", "1.0.200", "MIT"),
    ]);
    assert_eq!(sbom.format, "SPDX-2.3");
    assert_eq!(sbom.packages.len(), 2);
}

#[test]
fn sbom_diff_identical() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &b);
    assert!(result.added_packages.is_empty());
    assert!(result.removed_packages.is_empty());
}

#[test]
fn sbom_diff_added() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let mut b = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    b.packages.push(SbomPackage {
        name: "new".to_string(),
        version: "1.0".to_string(),
        supplier: None,
        licenses: vec![],
        checksum: None,
        purl: None,
    });
    let result = SbomDiffer::diff(&a, &b);
    assert_eq!(result.added_packages.len(), 1);
}

#[test]
fn sbom_diff_removed() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT"), ("pkg2", "2.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &b);
    assert_eq!(result.removed_packages.len(), 1);
    assert_eq!(result.removed_packages[0].name, "pkg2");
}

#[test]
fn sbom_diff_major_version_change() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "2.0.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &b);
    assert_eq!(result.changed_versions.len(), 1);
    assert!(result.changed_versions[0].major_change);
}

#[test]
fn sbom_diff_minor_version_change() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "1.1.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &b);
    assert_eq!(result.changed_versions.len(), 1);
    assert!(!result.changed_versions[0].major_change);
}

#[test]
fn sbom_diff_serde_roundtrip() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &b);
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: SbomDiffResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.summary, deserialized.summary);
}

#[test]
fn sbom_diff_summary_no_changes() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &a);
    assert!(result.summary.contains("No changes"));
}

#[test]
fn sbom_diff_summary_with_changes() {
    let a = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    let mut b = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
    b.packages.push(SbomPackage {
        name: "new".to_string(),
        version: "1.0".to_string(),
        supplier: None,
        licenses: vec![],
        checksum: None,
        purl: None,
    });
    let result = SbomDiffer::diff(&a, &b);
    assert!(result.summary.contains("1 added"));
}

#[test]
fn sbom_package_struct() {
    let pkg = SbomPackage {
        name: "test".to_string(),
        version: "1.0".to_string(),
        supplier: Some("TestCo".to_string()),
        licenses: vec!["MIT".to_string()],
        checksum: Some("sha256:abc".to_string()),
        purl: None,
    };
    assert_eq!(pkg.supplier, Some("TestCo".to_string()));
}

#[test]
fn sbom_relationship_struct() {
    let rel = SbomRelationship {
        source: "app".to_string(),
        target: "lib".to_string(),
        rel_type: "DEPENDS_ON".to_string(),
    };
    assert_eq!(rel.rel_type, "DEPENDS_ON");
}

#[test]
fn version_change_struct() {
    let vc = VersionChange {
        name: "pkg".to_string(),
        old_version: "1.0.0".to_string(),
        new_version: "2.0.0".to_string(),
        major_change: true,
    };
    assert!(vc.major_change);
}

#[test]
fn sbom_serde_roundtrip() {
    let sbom = SbomDiffer::generate_sbom(&[("a", "1.0", "MIT")]);
    let json = serde_json::to_string(&sbom).unwrap();
    let deserialized: Sbom = serde_json::from_str(&json).unwrap();
    assert_eq!(sbom.packages.len(), deserialized.packages.len());
}

#[test]
fn sbom_package_serde_roundtrip() {
    let pkg = SbomPackage {
        name: "t".to_string(),
        version: "1.0".to_string(),
        supplier: None,
        licenses: vec!["MIT".to_string()],
        checksum: None,
        purl: Some("pkg:cargo/t@1.0".to_string()),
    };
    let json = serde_json::to_string(&pkg).unwrap();
    let deserialized: SbomPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg.name, deserialized.name);
}

#[test]
fn slsa_verifier_new() {
    let _verifier = SlsaVerifier::new();
}

#[test]
fn slsa_verifier_default() {
    let _verifier = SlsaVerifier;
}

#[test]
fn slsa_verify_l3() {
    let prov = SlsaVerifier::generate_provenance(
        "https://github.com/example/builder",
        "https://github.com/example/repo",
        &[("src.tar.gz", "sha256:abc")],
    );
    let result = SlsaVerifier::verify(&prov, SlsaLevel::L3);
    assert!(result.proven);
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
    let result = SlsaVerifier::verify(&prov, SlsaLevel::L1);
    assert!(!result.proven);
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
fn slsa_level_serde_roundtrip() {
    let levels = vec![
        SlsaLevel::None,
        SlsaLevel::L1,
        SlsaLevel::L2,
        SlsaLevel::L3,
        SlsaLevel::L4,
    ];
    for level in levels {
        let json = serde_json::to_string(&level).unwrap();
        let deserialized: SlsaLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, deserialized);
    }
}

#[test]
fn slsa_generate_provenance() {
    let prov = SlsaVerifier::generate_provenance(
        "builder",
        "https://repo.example.com",
        &[("a.tar.gz", "sha256:aaa")],
    );
    assert_eq!(prov.builder.id, "builder");
    assert_eq!(prov.materials.len(), 1);
    assert_eq!(prov.byproducts.len(), 1);
}

#[test]
fn slsa_verification_result_serde() {
    let prov = SlsaVerifier::generate_provenance("b", "r", &[]);
    let result = SlsaVerifier::verify(&prov, SlsaLevel::L1);
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: SlsaVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.level, deserialized.level);
    assert_eq!(result.proven, deserialized.proven);
}

#[test]
fn slsa_provenance_serde_roundtrip() {
    let prov = SlsaVerifier::generate_provenance(
        "builder",
        "https://repo.example.com",
        &[("src.tar.gz", "sha256:abc")],
    );
    let json = serde_json::to_string(&prov).unwrap();
    let deserialized: SlsaProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(prov.builder.id, deserialized.builder.id);
    assert_eq!(prov.materials.len(), deserialized.materials.len());
}

#[test]
fn slsa_check_struct() {
    let check = SlsaCheck {
        name: "test".to_string(),
        passed: true,
        description: "desc".to_string(),
    };
    assert!(check.passed);
}

#[test]
fn slsa_check_serde_roundtrip() {
    let check = SlsaCheck {
        name: "test".to_string(),
        passed: true,
        description: "d".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let deserialized: SlsaCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check.name, deserialized.name);
    assert_eq!(check.passed, deserialized.passed);
}

#[test]
fn slsa_verify_l2_with_materials() {
    let prov = SlsaVerifier::generate_provenance(
        "builder-id",
        "https://github.com/example/repo",
        &[("src.tar.gz", "sha256:abc")],
    );
    let result = SlsaVerifier::verify(&prov, SlsaLevel::L2);
    assert!(result.proven);
}

#[test]
fn slsa_verify_l4_not_met() {
    let prov = SlsaVerifier::generate_provenance(
        "builder",
        "https://repo.example.com/build",
        &[("src.tar.gz", "sha256:abc")],
    );
    let result = SlsaVerifier::verify(&prov, SlsaLevel::L4);
    assert!(!result.proven);
}

#[test]
fn slsa_generate_multiple_materials() {
    let prov = SlsaVerifier::generate_provenance(
        "b",
        "r",
        &[("a.tar.gz", "sha256:aaa"), ("b.tar.gz", "sha256:bbb")],
    );
    assert_eq!(prov.materials.len(), 2);
    assert_eq!(prov.materials[0].uri, "a.tar.gz");
    assert_eq!(prov.materials[1].digest, "sha256:bbb");
}

#[test]
fn slsa_verify_empty_builder() {
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
    let result = SlsaVerifier::verify(&prov, SlsaLevel::None);
    assert!(result.proven);
}

#[test]
fn osv_severity_struct_serde() {
    let sev = OsvSeverity {
        c_type: "CVSS_V3".to_string(),
        score: "9.8".to_string(),
    };
    let json = serde_json::to_string(&sev).unwrap();
    let deserialized: OsvSeverity = serde_json::from_str(&json).unwrap();
    assert_eq!(sev.score, deserialized.score);
}

#[test]
fn osv_affected_struct_serde() {
    let aff = OsvAffected {
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
    let json = serde_json::to_string(&aff).unwrap();
    let deserialized: OsvAffected = serde_json::from_str(&json).unwrap();
    assert_eq!(aff.versions.len(), deserialized.versions.len());
}

#[test]
fn github_advisory_vuln_struct() {
    let v = AdvisoryVuln {
        package: "pkg".to_string(),
        ecosystem: "crates.io".to_string(),
        vulnerable_version_range: "< 2.0".to_string(),
        first_patched_version: Some("2.0".to_string()),
    };
    assert_eq!(v.ecosystem, "crates.io");
}

#[test]
fn github_advisory_serde_roundtrip() {
    let result = GithubAdvisoryClient::query("openssl", "crates.io");
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: AdvisoryQueryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.advisories.len(), deserialized.advisories.len());
}

#[test]
fn nvd_cvss_v3_struct() {
    let cvss = CvssV3 {
        version: "3.1".to_string(),
        vector_string: "CVSS:3.1/AV:N".to_string(),
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
    assert_eq!(cvss.base_score, 9.8);
}

#[test]
fn nvd_cvss_v2_struct() {
    let cvss = CvssV2 {
        version: "2.0".to_string(),
        base_score: 5.0,
        severity: "MEDIUM".to_string(),
    };
    assert_eq!(cvss.base_score, 5.0);
}

#[test]
fn nvd_metrics_serde_roundtrip() {
    let metrics = NvdMetrics {
        cvss_v3: Some(CvssV3 {
            version: "3.1".to_string(),
            vector_string: "CVSS:3.1/AV:N".to_string(),
            base_score: 7.5,
            base_severity: "HIGH".to_string(),
            attack_vector: "Network".to_string(),
            attack_complexity: "Low".to_string(),
            privileges_required: "None".to_string(),
            user_interaction: "None".to_string(),
            scope: "Unchanged".to_string(),
            confidentiality: "High".to_string(),
            integrity: "High".to_string(),
            availability: "High".to_string(),
        }),
        cvss_v2: None,
    };
    let json = serde_json::to_string(&metrics).unwrap();
    let deserialized: NvdMetrics = serde_json::from_str(&json).unwrap();
    assert!(deserialized.cvss_v3.is_some());
    assert!(deserialized.cvss_v2.is_none());
}

#[test]
fn nvd_reference_struct() {
    let r = NvdReference {
        url: "https://nvd.nist.gov".to_string(),
        tags: vec!["Patch".to_string()],
    };
    assert_eq!(r.tags.len(), 1);
}

#[test]
fn nvd_weakness_struct() {
    let w = NvdWeakness {
        c_type: "CWE-119".to_string(),
        description: vec![LangString {
            lang: "en".to_string(),
            value: "Buffer Overflow".to_string(),
        }],
    };
    assert_eq!(w.c_type, "CWE-119");
}

#[test]
fn cis_benchmark_compliance_pct() {
    let result = CisScanner::scan_docker("hostname read-only /var/run/docker.sock");
    let total = result.total_checks;
    let _passed = result.passed;
    if total > 0 {
        assert!(result.compliance_pct >= 0.0);
        assert!(result.compliance_pct <= 100.0);
    }
}

#[test]
fn sbom_diff_multiple_added_removed() {
    let a = SbomDiffer::generate_sbom(&[("x", "1.0", "MIT"), ("y", "2.0", "MIT")]);
    let b = SbomDiffer::generate_sbom(&[("x", "1.0", "MIT"), ("z", "3.0", "MIT")]);
    let result = SbomDiffer::diff(&a, &b);
    assert_eq!(result.added_packages.len(), 1);
    assert_eq!(result.removed_packages.len(), 1);
}

#[test]
fn license_audit_single_permissive() {
    let deps = vec![("pkg", "1.0", "ISC")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.compliance_pct, 100.0);
}

#[test]
fn license_audit_weak_protective_allowed() {
    let deps = vec![("pkg", "1.0", "MPL-2.0")];
    let audit = LicenseChecker::audit(&deps);
    assert_eq!(audit.allowed.len(), 1);
}
