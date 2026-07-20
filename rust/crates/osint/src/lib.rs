pub mod collector;
pub mod darkweb;
pub mod dns;
pub mod email;
pub mod infra;
pub mod person;
pub mod report;
pub mod search;
pub mod social;
pub mod throttle;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintTarget {
    pub value: String,
    pub kind: TargetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetKind {
    Domain,
    Email,
    IpAddress,
    Username,
    Url,
    Organization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintFinding {
    pub source: OsintSource,
    pub kind: FindingKind,
    pub value: String,
    pub context: Option<String>,
    pub confidence: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintSource {
    pub name: String,
    pub reliability: Reliability,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reliability {
    High,
    Medium,
    Low,
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FindingKind {
    Email,
    Url,
    IpAddress,
    PhoneNumber,
    Username,
    DnsRecord,
    WhoisInfo,
    Technology,
    Subdomain,
    SocialProfile,
    BreachData,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintReport {
    pub target: OsintTarget,
    pub findings: Vec<OsintFinding>,
    pub summary: String,
    pub collected_at: String,
    pub source_count: usize,
}

impl OsintReport {
    pub fn new(target: OsintTarget, findings: Vec<OsintFinding>) -> Self {
        let collected_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut sources: Vec<&str> = findings.iter().map(|f| f.source.name.as_str()).collect();
        sources.sort_unstable();
        sources.dedup();
        let source_count = sources.len();
        let summary = format!(
            "Collected {} findings from {} sources for target '{}'",
            findings.len(),
            source_count,
            target.value
        );
        Self {
            target,
            findings,
            summary,
            collected_at,
            source_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osint_target_struct() {
        let t = OsintTarget { value: "example.com".into(), kind: TargetKind::Domain };
        assert_eq!(t.value, "example.com");
        assert!(matches!(t.kind, TargetKind::Domain));
    }

    #[test]
    fn target_kind_variants() {
        let variants = [TargetKind::Domain, TargetKind::Email, TargetKind::IpAddress, TargetKind::Username, TargetKind::Url, TargetKind::Organization];
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn osint_finding_confidence_range() {
        let f = OsintFinding {
            source: OsintSource { name: "test".into(), reliability: Reliability::High, url: None },
            kind: FindingKind::Email,
            value: "test@example.com".into(),
            context: None,
            confidence: 0.95,
            timestamp: "2024-01-01T00:00:00Z".into(),
        };
        assert!(f.confidence >= 0.0 && f.confidence <= 1.0);
    }

    #[test]
    fn reliability_variants() {
        assert!(matches!(Reliability::High, Reliability::High));
        assert!(matches!(Reliability::Medium, Reliability::Medium));
        assert!(matches!(Reliability::Low, Reliability::Low));
        assert!(matches!(Reliability::Untrusted, Reliability::Untrusted));
    }

    #[test]
    fn finding_kind_custom() {
        let fk = FindingKind::Custom("TestKind".into());
        if let FindingKind::Custom(s) = fk {
            assert_eq!(s, "TestKind");
        } else {
            panic!("expected Custom");
        }
    }

    #[test]
    fn osint_report_summary_format() {
        let t = OsintTarget { value: "test.com".into(), kind: TargetKind::Domain };
        let report = OsintReport::new(t, vec![]);
        assert!(report.summary.contains("0 findings"));
        assert!(report.summary.contains("test.com"));
    }

    #[test]
    fn osint_report_source_count() {
        let t = OsintTarget { value: "test.com".into(), kind: TargetKind::Domain };
        let findings = vec![
            OsintFinding {
                source: OsintSource { name: "a".into(), reliability: Reliability::High, url: None },
                kind: FindingKind::Email,
                value: "a@b.com".into(),
                context: None,
                confidence: 0.9,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
            OsintFinding {
                source: OsintSource { name: "a".into(), reliability: Reliability::High, url: None },
                kind: FindingKind::Email,
                value: "c@d.com".into(),
                context: None,
                confidence: 0.9,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
            OsintFinding {
                source: OsintSource { name: "b".into(), reliability: Reliability::Medium, url: None },
                kind: FindingKind::Url,
                value: "https://example.com".into(),
                context: None,
                confidence: 0.7,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
        ];
        let report = OsintReport::new(t, findings);
        assert_eq!(report.source_count, 2);
        assert_eq!(report.findings.len(), 3);
    }

    #[test]
    fn osint_target_serialization() {
        let t = OsintTarget { value: "test.com".into(), kind: TargetKind::Domain };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("test.com"));
    }

    #[test]
    fn osint_finding_serialization() {
        let f = OsintFinding {
            source: OsintSource { name: "test".into(), reliability: Reliability::High, url: None },
            kind: FindingKind::Email,
            value: "test@example.com".into(),
            context: Some("context".into()),
            confidence: 0.95,
            timestamp: "2024-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn osint_source_struct() {
        let s = OsintSource { name: "test".into(), reliability: Reliability::Low, url: Some("https://test.com".into()) };
        assert_eq!(s.name, "test");
        assert!(s.url.is_some());
    }

    #[test]
    fn finding_kind_equality() {
        assert_eq!(FindingKind::Email, FindingKind::Email);
        assert_ne!(FindingKind::Email, FindingKind::Url);
        assert_eq!(FindingKind::Custom("x".into()), FindingKind::Custom("x".into()));
        assert_ne!(FindingKind::Custom("x".into()), FindingKind::Custom("y".into()));
    }

    #[test]
    fn target_kind_serialization() {
        let kinds = [TargetKind::Domain, TargetKind::Email, TargetKind::IpAddress, TargetKind::Username, TargetKind::Url, TargetKind::Organization];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let _back: TargetKind = serde_json::from_str(&json).unwrap();
        }
    }
}
