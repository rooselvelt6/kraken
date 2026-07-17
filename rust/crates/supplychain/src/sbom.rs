use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub format: String,
    pub spec_version: String,
    pub packages: Vec<SbomPackage>,
    pub relationships: Vec<SbomRelationship>,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    pub supplier: Option<String>,
    pub licenses: Vec<String>,
    pub checksum: Option<String>,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomRelationship {
    pub source: String,
    pub target: String,
    pub rel_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDiffResult {
    pub version_a: String,
    pub version_b: String,
    pub added_packages: Vec<SbomPackage>,
    pub removed_packages: Vec<SbomPackage>,
    pub changed_versions: Vec<VersionChange>,
    pub added_dependencies: Vec<String>,
    pub removed_dependencies: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionChange {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub major_change: bool,
}

pub struct SbomDiffer;

impl Default for SbomDiffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomDiffer {
    pub fn new() -> Self {
        SbomDiffer
    }

    pub fn diff(sbom_a: &Sbom, sbom_b: &Sbom) -> SbomDiffResult {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        let map_a: HashMap<&str, &SbomPackage> = sbom_a.packages.iter().map(|p| (p.name.as_str(), p)).collect();
        let map_b: HashMap<&str, &SbomPackage> = sbom_b.packages.iter().map(|p| (p.name.as_str(), p)).collect();

        for (name, pkg_b) in &map_b {
            if let Some(pkg_a) = map_a.get(name) {
                if pkg_a.version != pkg_b.version {
                    let major = Self::is_major_version_change(&pkg_a.version, &pkg_b.version);
                    changed.push(VersionChange {
                        name: name.to_string(),
                        old_version: pkg_a.version.clone(),
                        new_version: pkg_b.version.clone(),
                        major_change: major,
                    });
                }
            } else {
                added.push((*pkg_b).clone());
            }
        }

        for (name, pkg_a) in &map_a {
            if !map_b.contains_key(name) {
                removed.push((*pkg_a).clone());
            }
        }

        let added_deps = Self::find_new_deps(sbom_a, sbom_b);
        let removed_deps = Self::find_removed_deps(sbom_a, sbom_b);

        let summary = if added.is_empty() && removed.is_empty() && changed.is_empty() {
            "No changes between SBOM versions".to_string()
        } else {
            format!(
                "{} added, {} removed, {} version changes ({} major)",
                added.len(),
                removed.len(),
                changed.len(),
                changed.iter().filter(|c| c.major_change).count()
            )
        };

        SbomDiffResult {
            version_a: sbom_a.created.clone(),
            version_b: sbom_b.created.clone(),
            added_packages: added,
            removed_packages: removed,
            changed_versions: changed,
            added_dependencies: added_deps,
            removed_dependencies: removed_deps,
            summary,
        }
    }

    fn is_major_version_change(old_ver: &str, new_ver: &str) -> bool {
        let parse_major = |v: &str| -> Option<u64> {
            v.split('.').next()?.parse().ok()
        };
        match (parse_major(old_ver), parse_major(new_ver)) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }

    fn find_new_deps(a: &Sbom, b: &Sbom) -> Vec<String> {
        let rels_a: Vec<&str> = a.relationships.iter().map(|r| r.target.as_str()).collect();
        let mut new_deps = Vec::new();
        for rel in &b.relationships {
            if !rels_a.contains(&rel.target.as_str()) {
                new_deps.push(rel.target.clone());
            }
        }
        new_deps
    }

    fn find_removed_deps(a: &Sbom, b: &Sbom) -> Vec<String> {
        let rels_b: Vec<&str> = b.relationships.iter().map(|r| r.target.as_str()).collect();
        let mut removed = Vec::new();
        for rel in &a.relationships {
            if !rels_b.contains(&rel.target.as_str()) {
                removed.push(rel.target.clone());
            }
        }
        removed
    }

    pub fn generate_sbom(packages: &[(&str, &str, &str)]) -> Sbom {
        let sbom_packages: Vec<SbomPackage> = packages.iter().map(|&(name, version, license)| {
            SbomPackage {
                name: name.to_string(),
                version: version.to_string(),
                supplier: None,
                licenses: vec![license.to_string()],
                checksum: None,
                purl: Some(format!("pkg:cargo/{}@{}", name, version)),
            }
        }).collect();

        let relationships: Vec<SbomRelationship> = sbom_packages.iter().skip(1).map(|p| {
            SbomRelationship {
                source: sbom_packages[0].name.clone(),
                target: p.name.clone(),
                rel_type: "DEPENDS_ON".to_string(),
            }
        }).collect();

        Sbom {
            format: "SPDX-2.3".to_string(),
            spec_version: "SPDX-2.3".to_string(),
            packages: sbom_packages,
            relationships,
            created: "now".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sbom() -> Sbom {
        SbomDiffer::generate_sbom(&[
            ("app", "1.0.0", "MIT"),
            ("serde", "1.0.200", "MIT"),
            ("reqwest", "0.11.0", "MIT"),
        ])
    }

    #[test]
    fn test_diff_identical() {
        let a = sample_sbom();
        let b = sample_sbom();
        let result = SbomDiffer::diff(&a, &b);
        assert_eq!(result.added_packages.len(), 0);
        assert_eq!(result.removed_packages.len(), 0);
    }

    #[test]
    fn test_diff_added() {
        let a = sample_sbom();
        let mut b = sample_sbom();
        b.packages.push(SbomPackage {
            name: "new-dep".to_string(),
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
    fn test_diff_removed() {
        let a = sample_sbom();
        let mut b = sample_sbom();
        b.packages.pop();
        let result = SbomDiffer::diff(&a, &b);
        assert_eq!(result.removed_packages.len(), 1);
    }

    #[test]
    fn test_diff_version_change() {
        let a = sample_sbom();
        let mut b = sample_sbom();
        if let Some(pkg) = b.packages.iter_mut().find(|p| p.name == "serde") {
            pkg.version = "2.0.0".to_string();
        }
        let result = SbomDiffer::diff(&a, &b);
        assert!(!result.changed_versions.is_empty());
    }

    #[test]
    fn test_generate_sbom() {
        let sbom = sample_sbom();
        assert_eq!(sbom.format, "SPDX-2.3");
        assert_eq!(sbom.packages.len(), 3);
    }

    #[test]
    fn test_sbom_diff_serde() {
        let a = sample_sbom();
        let b = sample_sbom();
        let result = SbomDiffer::diff(&a, &b);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("version_a"));
    }
}
