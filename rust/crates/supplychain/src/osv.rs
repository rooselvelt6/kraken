use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvQuery {
    pub package: OsvPackage,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvResponse {
    pub vulns: Vec<OsvVuln>,
    pub query: OsvQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub summary: String,
    pub severity: Vec<OsvSeverity>,
    pub affected: Vec<OsvAffected>,
    pub references: Vec<String>,
    pub published: String,
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    pub c_type: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    pub package: OsvPackage,
    pub ranges: Vec<OsvRange>,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    pub c_type: String,
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

pub struct OsvClient;

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OsvClient {
    pub fn new() -> Self {
        OsvClient
    }

    pub fn query(name: &str, ecosystem: &str, version: Option<&str>) -> OsvResponse {
        let query = OsvQuery {
            package: OsvPackage {
                name: name.to_string(),
                ecosystem: ecosystem.to_string(),
                purl: None,
            },
            version: version.map(|v| v.to_string()),
        };

        let vulns = Self::match_vulns(name, ecosystem, version);

        OsvResponse { vulns, query }
    }

    fn match_vulns(name: &str, ecosystem: &str, version: Option<&str>) -> Vec<OsvVuln> {
        let mut vulns = Vec::new();
        let db = Self::sample_db();
        for vuln in db {
            for affected in &vuln.affected {
                if affected.package.name == name && affected.package.ecosystem == ecosystem {
                    if let Some(ver) = version {
                        if Self::is_affected(ver, &affected.ranges) {
                            vulns.push(vuln.clone());
                        }
                    } else {
                        vulns.push(vuln.clone());
                    }
                }
            }
        }
        vulns
    }

    fn is_affected(version: &str, ranges: &[OsvRange]) -> bool {
        for range in ranges {
            let mut introduced: Option<semver::Version> = None;
            let mut fixed: Option<semver::Version> = None;

            for event in &range.events {
                if let Some(v) = &event.introduced {
                    introduced = semver::Version::parse(v).ok();
                }
                if let Some(v) = &event.fixed {
                    fixed = semver::Version::parse(v).ok();
                }
            }

            let ver = semver::Version::parse(version);
            if let Ok(ref v) = ver {
                match (introduced, fixed) {
                    (Some(low), Some(high)) if v >= &low && v < &high => return true,
                    (Some(low), None) if v >= &low => return true,
                    _ => {}
                }
            }
        }
        false
    }

    fn sample_db() -> Vec<OsvVuln> {
        vec![
            OsvVuln {
                id: "GHSA-xxxx-xxxx-xxxx".to_string(),
                summary: "Sample vulnerability in openssl 1.0.x".to_string(),
                severity: vec![OsvSeverity { c_type: "CVSS_V3".to_string(), score: "7.5".to_string() }],
                affected: vec![OsvAffected {
                    package: OsvPackage { name: "openssl".to_string(), ecosystem: "crates.io".to_string(), purl: None },
                    ranges: vec![OsvRange {
                        c_type: "SEMVER".to_string(),
                        events: vec![
                            OsvEvent { introduced: Some("1.0.0".to_string()), fixed: Some("1.0.3".to_string()) },
                        ],
                    }],
                    versions: vec![],
                }],
                references: vec!["https://example.com/cve".to_string()],
                published: "2024-01-01".to_string(),
                modified: "2024-06-01".to_string(),
            },
            OsvVuln {
                id: "GHSA-yyyy-yyyy-yyyy".to_string(),
                summary: "Critical RCE in log4j".to_string(),
                severity: vec![OsvSeverity { c_type: "CVSS_V3".to_string(), score: "10.0".to_string() }],
                affected: vec![OsvAffected {
                    package: OsvPackage { name: "log4j".to_string(), ecosystem: "Maven".to_string(), purl: None },
                    ranges: vec![OsvRange {
                        c_type: "SEMVER".to_string(),
                        events: vec![
                            OsvEvent { introduced: Some("2.0.0".to_string()), fixed: Some("2.17.0".to_string()) },
                        ],
                    }],
                    versions: vec![],
                }],
                references: vec!["https://nvd.nist.gov".to_string()],
                published: "2021-12-09".to_string(),
                modified: "2023-01-01".to_string(),
            },
        ]
    }
}

mod semver {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Version {
        pub major: u64,
        pub minor: u64,
        pub patch: u64,
    }

    impl Version {
        pub fn parse(s: &str) -> Result<Self, ()> {
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() < 2 {
                return Err(());
            }
            let major = parts[0].parse().map_err(|_| ())?;
            let minor = parts[1].parse().map_err(|_| ())?;
            let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
            Ok(Version { major, minor, patch })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_with_version() {
        let resp = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
        assert!(!resp.vulns.is_empty());
    }

    #[test]
    fn test_query_without_version() {
        let resp = OsvClient::query("openssl", "crates.io", None);
        assert!(!resp.vulns.is_empty());
    }

    #[test]
    fn test_query_no_match() {
        let resp = OsvClient::query("nonexistent", "crates.io", None);
        assert!(resp.vulns.is_empty());
    }

    #[test]
    fn test_query_log4j() {
        let resp = OsvClient::query("log4j", "Maven", Some("2.14.0"));
        assert!(!resp.vulns.is_empty());
    }

    #[test]
    fn test_osv_response_serde() {
        let resp = OsvClient::query("test", "crates.io", None);
        let json = serde_json::to_string_pretty(&resp).unwrap();
        assert!(json.contains("test"));
    }

    #[test]
    fn test_query_openssl_fixed_version() {
        let resp = OsvClient::query("openssl", "crates.io", Some("1.0.5"));
        assert!(resp.vulns.is_empty());
    }

    #[test]
    fn test_query_ecosystem_mismatch() {
        let resp = OsvClient::query("openssl", "npm", Some("1.0.2"));
        assert!(resp.vulns.is_empty());
    }

    #[test]
    fn test_osv_vuln_struct() {
        let vuln = OsvVuln {
            id: "TEST-001".to_string(),
            summary: "test vuln".to_string(),
            severity: vec![OsvSeverity { c_type: "CVSS_V3".to_string(), score: "5.0".to_string() }],
            affected: vec![],
            references: vec![],
            published: "2024-01-01".to_string(),
            modified: "2024-06-01".to_string(),
        };
        assert_eq!(vuln.id, "TEST-001");
        assert_eq!(vuln.severity.len(), 1);
    }

    #[test]
    fn test_osv_query_struct() {
        let query = OsvQuery {
            package: OsvPackage {
                name: "test".to_string(),
                ecosystem: "crates.io".to_string(),
                purl: Some("pkg:cargo/test@1.0".to_string()),
            },
            version: Some("1.0.0".to_string()),
        };
        assert_eq!(query.package.name, "test");
        assert!(query.version.is_some());
    }

    #[test]
    fn test_osv_severity_struct() {
        let sev = OsvSeverity {
            c_type: "CVSS_V3".to_string(),
            score: "9.8".to_string(),
        };
        assert_eq!(sev.score, "9.8");
    }

    #[test]
    fn test_osv_affected_struct() {
        let aff = OsvAffected {
            package: OsvPackage { name: "test".to_string(), ecosystem: "crates.io".to_string(), purl: None },
            ranges: vec![OsvRange {
                c_type: "SEMVER".to_string(),
                events: vec![OsvEvent { introduced: Some("1.0.0".to_string()), fixed: Some("2.0.0".to_string()) }],
            }],
            versions: vec!["1.0.0".to_string(), "1.1.0".to_string()],
        };
        assert_eq!(aff.versions.len(), 2);
    }

    #[test]
    fn test_osv_client_default() {
        let client = OsvClient::default();
        let resp = OsvClient::query("test", "crates.io", None);
        assert_eq!(resp.vulns.len(), 0);
    }

    #[test]
    fn test_query_preserves_version() {
        let resp = OsvClient::query("openssl", "crates.io", Some("1.0.2"));
        assert_eq!(resp.query.version, Some("1.0.2".to_string()));
    }

    #[test]
    fn test_semver_parse() {
        let v = semver::Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_semver_parse_no_patch() {
        let v = semver::Version::parse("1.2").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_semver_parse_invalid() {
        assert!(semver::Version::parse("abc").is_err());
        assert!(semver::Version::parse("").is_err());
    }
}
