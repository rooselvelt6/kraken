use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseAudit {
    pub total_dependencies: usize,
    pub allowed: Vec<LicenseEntry>,
    pub restricted: Vec<LicenseEntry>,
    pub unknown: Vec<LicenseEntry>,
    pub compliance_pct: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseEntry {
    pub package: String,
    pub version: String,
    pub license: String,
    pub category: LicenseCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LicenseCategory {
    Permissive,
    WeakProtective,
    StrongProtective,
    Restricted,
    Unknown,
}

const ALLOWED_LICENSES: &[&str] = &[
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unlicense", "CC0-1.0", "MPL-2.0",
    "Zlib", "ICU", "Python-2.0", "PostgreSQL",
];

const RESTRICTED_LICENSES: &[&str] = &[
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "EUPL-1.2", "CC-BY-NC-4.0", "BUSL-1.1",
];

pub struct LicenseChecker;

impl Default for LicenseChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseChecker {
    /// Creates a new license checker.
    pub fn new() -> Self {
        LicenseChecker
    }

    /// Audits a list of dependencies for license compliance.
    ///
    /// # Examples
    ///
    /// ```
    /// use supplychain::LicenseChecker;
    ///
    /// let deps = vec![
    ///     ("serde", "1.0", "MIT"),
    ///     ("reqwest", "0.11", "Apache-2.0"),
    ///     ("gpl-pkg", "2.0", "GPL-3.0-only"),
    /// ];
    /// let audit = LicenseChecker::audit(&deps);
    /// assert_eq!(audit.total_dependencies, 3);
    /// assert_eq!(audit.allowed.len(), 2);
    /// assert_eq!(audit.restricted.len(), 1);
    /// assert!(audit.compliance_pct < 100.0);
    /// ```
    pub fn audit(deps: &[(&str, &str, &str)]) -> LicenseAudit {
        let mut allowed = Vec::new();
        let mut restricted = Vec::new();
        let mut unknown = Vec::new();

        for &(name, version, license) in deps {
            let category = Self::categorize(license);
            let entry = LicenseEntry {
                package: name.to_string(),
                version: version.to_string(),
                license: license.to_string(),
                category: category.clone(),
            };
            match category {
                LicenseCategory::Restricted => restricted.push(entry),
                LicenseCategory::Unknown => unknown.push(entry),
                _ => allowed.push(entry),
            }
        }

        let total = deps.len();
        let compliance = if total > 0 {
            allowed.len() as f64 / total as f64 * 100.0
        } else {
            100.0
        };

        let mut recommendations = Vec::new();
        if !restricted.is_empty() {
            recommendations.push(format!(
                "Found {} restricted license(s): {}",
                restricted.len(),
                restricted.iter().map(|e| format!("{} ({})", e.package, e.license)).collect::<Vec<_>>().join(", ")
            ));
        }
        if !unknown.is_empty() {
            recommendations.push(format!(
                "Found {} package(s) with unknown licenses: review manually",
                unknown.len()
            ));
        }
        recommendations.push(format!("License compliance: {:.1}%", compliance));

        LicenseAudit {
            total_dependencies: total,
            allowed,
            restricted,
            unknown,
            compliance_pct: compliance,
            recommendations,
        }
    }

    fn categorize(license: &str) -> LicenseCategory {
        let lic = license.trim();
        if ALLOWED_LICENSES.contains(&lic) {
            if lic.starts_with("MPL") {
                LicenseCategory::WeakProtective
            } else {
                LicenseCategory::Permissive
            }
        } else if RESTRICTED_LICENSES.contains(&lic) {
            if lic.starts_with("LGPL") {
                LicenseCategory::WeakProtective
            } else if lic.starts_with("AGPL") {
                LicenseCategory::StrongProtective
            } else {
                LicenseCategory::Restricted
            }
        } else if lic.is_empty() || lic == "unknown" || lic == "UNKNOWN" {
            LicenseCategory::Unknown
        } else if lic.contains("Proprietary") || lic.contains("Commercial") {
            LicenseCategory::Restricted
        } else {
            LicenseCategory::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_all_permissive() {
        let deps = vec![
            ("serde", "1.0", "MIT"),
            ("reqwest", "0.11", "Apache-2.0"),
        ];
        let audit = LicenseChecker::audit(&deps);
        assert!(audit.restricted.is_empty());
        assert!(audit.compliance_pct > 90.0);
    }

    #[test]
    fn test_audit_with_restricted() {
        let deps = vec![
            ("pkg1", "1.0", "MIT"),
            ("pkg2", "2.0", "GPL-3.0-only"),
        ];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.restricted.len(), 1);
    }

    #[test]
    fn test_audit_unknown() {
        let deps = vec![("pkg", "1.0", "unknown")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.unknown.len(), 1);
    }

    #[test]
    fn test_audit_empty() {
        let audit = LicenseChecker::audit(&[]);
        assert_eq!(audit.total_dependencies, 0);
        assert_eq!(audit.compliance_pct, 100.0);
    }

    #[test]
    fn test_audit_serde() {
        let deps = vec![("test", "1.0", "MIT")];
        let audit = LicenseChecker::audit(&deps);
        let json = serde_json::to_string_pretty(&audit).unwrap();
        assert!(json.contains("MIT"));
    }

    #[test]
    fn test_categorize_mpl() {
        let deps = vec![("pkg", "1.0", "MPL-2.0")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.allowed.len(), 1);
        assert_eq!(audit.allowed[0].category, LicenseCategory::WeakProtective);
    }

    #[test]
    fn test_categorize_lgpl() {
        let deps = vec![("pkg", "1.0", "LGPL-3.0-only")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.allowed.len(), 1);
        assert_eq!(audit.allowed[0].category, LicenseCategory::WeakProtective);
    }

    #[test]
    fn test_categorize_agpl() {
        let deps = vec![("pkg", "1.0", "AGPL-3.0-only")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.allowed.len(), 1);
        assert_eq!(audit.allowed[0].category, LicenseCategory::StrongProtective);
    }

    #[test]
    fn test_categorize_proprietary() {
        let deps = vec![("pkg", "1.0", "Proprietary")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.restricted.len(), 1);
    }

    #[test]
    fn test_categorize_commercial() {
        let deps = vec![("pkg", "1.0", "Commercial")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.restricted.len(), 1);
    }

    #[test]
    fn test_categorize_empty_license() {
        let deps = vec![("pkg", "1.0", "")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.unknown.len(), 1);
    }

    #[test]
    fn test_categorize_uppercase_unknown() {
        let deps = vec![("pkg", "1.0", "UNKNOWN")];
        let audit = LicenseChecker::audit(&deps);
        assert_eq!(audit.unknown.len(), 1);
    }

    #[test]
    fn test_audit_compliance_calculation() {
        let deps = vec![
            ("a", "1.0", "MIT"),
            ("b", "1.0", "MIT"),
            ("c", "1.0", "GPL-3.0-only"),
        ];
        let audit = LicenseChecker::audit(&deps);
        assert!((audit.compliance_pct - 66.6).abs() < 1.0);
    }

    #[test]
    fn test_audit_recommendations_restricted() {
        let deps = vec![("pkg", "1.0", "GPL-3.0-only")];
        let audit = LicenseChecker::audit(&deps);
        assert!(audit.recommendations.iter().any(|r| r.contains("restricted")));
    }

    #[test]
    fn test_audit_recommendations_unknown() {
        let deps = vec![("pkg", "1.0", "SomeWeirdLicense")];
        let audit = LicenseChecker::audit(&deps);
        assert!(audit.recommendations.iter().any(|r| r.contains("unknown")));
    }

    #[test]
    fn test_audit_recommendations_compliance() {
        let deps = vec![("pkg", "1.0", "MIT")];
        let audit = LicenseChecker::audit(&deps);
        assert!(audit.recommendations.iter().any(|r| r.contains("100.0%")));
    }

    #[test]
    fn test_license_entry_struct() {
        let entry = LicenseEntry {
            package: "test".to_string(),
            version: "1.0".to_string(),
            license: "MIT".to_string(),
            category: LicenseCategory::Permissive,
        };
        assert_eq!(entry.category, LicenseCategory::Permissive);
    }

    #[test]
    fn test_license_checker_default() {
        let checker = LicenseChecker::default();
        let audit = LicenseChecker::audit(&[]);
        assert_eq!(audit.total_dependencies, 0);
    }
}
