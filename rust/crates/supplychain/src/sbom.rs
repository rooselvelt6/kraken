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
pub struct CycloneDx {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub components: Vec<CycloneComponent>,
    pub dependencies: Vec<CycloneDependency>,
    pub metadata: CycloneMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneComponent {
    pub r#type: String,
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub scopes: Vec<String>,
    pub hashes: Vec<CycloneHash>,
    pub licenses: Vec<CycloneLicense>,
    pub purl: Option<String>,
    pub external_references: Vec<CycloneExternalRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneLicense {
    pub license: CycloneLicenseChoice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneLicenseChoice {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneExternalRef {
    pub r#type: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDependency {
    pub ref_: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneMetadata {
    pub timestamp: String,
    pub tools: Vec<CycloneTool>,
    pub component: Option<CycloneComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
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

    pub fn to_cyclonedx(sbom: &Sbom) -> CycloneDx {
        let components: Vec<CycloneComponent> = sbom.packages.iter().enumerate().map(|(i, pkg)| {
            CycloneComponent {
                r#type: "library".to_string(),
                bom_ref: format!("component-{}", i),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                description: None,
                scopes: vec!["required".to_string()],
                hashes: pkg.checksum.as_ref().map(|c| {
                    vec![CycloneHash {
                        alg: "SHA-256".to_string(),
                        content: c.clone(),
                    }]
                }).unwrap_or_default(),
                licenses: pkg.licenses.iter().map(|l| {
                    CycloneLicense {
                        license: CycloneLicenseChoice {
                            id: None,
                            name: Some(l.clone()),
                        },
                    }
                }).collect(),
                purl: pkg.purl.clone(),
                external_references: vec![],
            }
        }).collect();

        let dependencies: Vec<CycloneDependency> = sbom.relationships.iter().map(|r| {
            CycloneDependency {
                ref_: r.source.clone(),
                depends_on: vec![r.target.clone()],
            }
        }).collect();

        let metadata = CycloneMetadata {
            timestamp: sbom.created.clone(),
            tools: vec![CycloneTool {
                vendor: "Kraken".to_string(),
                name: "kraken-supplychain".to_string(),
                version: "2.0.0".to_string(),
            }],
            component: components.first().cloned(),
        };

        CycloneDx {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            version: 1,
            components,
            dependencies,
            metadata,
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

    #[test]
    fn test_diff_major_version_change() {
        let a = SbomDiffer::generate_sbom(&[("pkg", "1.0.0", "MIT")]);
        let mut b = SbomDiffer::generate_sbom(&[("pkg", "2.0.0", "MIT")]);
        let result = SbomDiffer::diff(&a, &b);
        assert_eq!(result.changed_versions.len(), 1);
        assert!(result.changed_versions[0].major_change);
    }

    #[test]
    fn test_diff_minor_version_change() {
        let a = SbomDiffer::generate_sbom(&[("pkg", "1.0.0", "MIT")]);
        let mut b = SbomDiffer::generate_sbom(&[("pkg", "1.1.0", "MIT")]);
        let result = SbomDiffer::diff(&a, &b);
        assert_eq!(result.changed_versions.len(), 1);
        assert!(!result.changed_versions[0].major_change);
    }

    #[test]
    fn test_diff_no_changes_summary() {
        let a = sample_sbom();
        let b = sample_sbom();
        let result = SbomDiffer::diff(&a, &b);
        assert!(result.summary.contains("No changes"));
    }

    #[test]
    fn test_diff_changes_summary() {
        let a = sample_sbom();
        let mut b = sample_sbom();
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
    fn test_generate_sbom_packages() {
        let sbom = SbomDiffer::generate_sbom(&[
            ("a", "1.0", "MIT"),
            ("b", "2.0", "Apache-2.0"),
            ("c", "3.0", "BSD-3-Clause"),
        ]);
        assert_eq!(sbom.packages.len(), 3);
        assert_eq!(sbom.relationships.len(), 2);
        assert_eq!(sbom.packages[0].purl, Some("pkg:cargo/a@1.0".to_string()));
    }

    #[test]
    fn test_sbom_package_struct() {
        let pkg = SbomPackage {
            name: "test".to_string(),
            version: "1.0".to_string(),
            supplier: Some("TestCo".to_string()),
            licenses: vec!["MIT".to_string()],
            checksum: Some("sha256:abc".to_string()),
            purl: None,
        };
        assert_eq!(pkg.supplier, Some("TestCo".to_string()));
        assert!(pkg.checksum.is_some());
    }

    #[test]
    fn test_sbom_relationship_struct() {
        let rel = SbomRelationship {
            source: "app".to_string(),
            target: "lib".to_string(),
            rel_type: "DEPENDS_ON".to_string(),
        };
        assert_eq!(rel.rel_type, "DEPENDS_ON");
    }

    #[test]
    fn test_version_change_struct() {
        let vc = VersionChange {
            name: "pkg".to_string(),
            old_version: "1.0.0".to_string(),
            new_version: "2.0.0".to_string(),
            major_change: true,
        };
        assert!(vc.major_change);
    }

    #[test]
    fn test_diff_multiple_added_and_removed() {
        let a = SbomDiffer::generate_sbom(&[("x", "1.0", "MIT"), ("y", "2.0", "MIT")]);
        let mut b = SbomDiffer::generate_sbom(&[("x", "1.0", "MIT"), ("z", "3.0", "MIT")]);
        let result = SbomDiffer::diff(&a, &b);
        assert_eq!(result.added_packages.len(), 1);
        assert_eq!(result.removed_packages.len(), 1);
        assert_eq!(result.added_packages[0].name, "z");
        assert_eq!(result.removed_packages[0].name, "y");
    }

    #[test]
    fn test_sbom_differ_default() {
        let differ = SbomDiffer::default();
        let sbom = SbomDiffer::generate_sbom(&[]);
        let result = SbomDiffer::diff(&sbom, &sbom);
        assert_eq!(result.added_packages.len(), 0);
    }

    #[test]
    fn test_cyclonedx_conversion() {
        let sbom = sample_sbom();
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom);
        assert_eq!(cyclonedx.bom_format, "CycloneDX");
        assert_eq!(cyclonedx.spec_version, "1.5");
        assert_eq!(cyclonedx.components.len(), 3);
        assert_eq!(cyclonedx.dependencies.len(), 2);
    }

    #[test]
    fn test_cyclonedx_component_structure() {
        let sbom = SbomDiffer::generate_sbom(&[("test-pkg", "1.0.0", "MIT")]);
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom);
        let component = &cyclonedx.components[0];
        assert_eq!(component.r#type, "library");
        assert_eq!(component.name, "test-pkg");
        assert_eq!(component.version, "1.0.0");
        assert_eq!(component.purl, Some("pkg:cargo/test-pkg@1.0.0".to_string()));
        assert!(!component.licenses.is_empty());
    }

    #[test]
    fn test_cyclonedx_metadata() {
        let sbom = sample_sbom();
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom);
        assert_eq!(cyclonedx.metadata.tools.len(), 1);
        assert_eq!(cyclonedx.metadata.tools[0].vendor, "Kraken");
        assert!(cyclonedx.metadata.timestamp.is_empty() || cyclonedx.metadata.timestamp == "now");
    }

    #[test]
    fn test_cyclonedx_serial_number_format() {
        let sbom = sample_sbom();
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom);
        assert!(cyclonedx.serial_number.starts_with("urn:uuid:"));
    }

    #[test]
    fn test_cyclonedx_hashes() {
        let sbom = SbomDiffer::generate_sbom(&[("pkg", "1.0", "MIT")]);
        let mut sbom_with_hash = sbom;
        sbom_with_hash.packages[0].checksum = Some("abc123".to_string());
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom_with_hash);
        assert!(!cyclonedx.components[0].hashes.is_empty());
        assert_eq!(cyclonedx.components[0].hashes[0].alg, "SHA-256");
    }

    #[test]
    fn test_cyclonedx_empty_sbom() {
        let sbom = SbomDiffer::generate_sbom(&[]);
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom);
        assert!(cyclonedx.components.is_empty());
        assert!(cyclonedx.dependencies.is_empty());
    }

    #[test]
    fn test_cyclonedx_dependencies() {
        let sbom = SbomDiffer::generate_sbom(&[("app", "1.0", "MIT"), ("lib", "2.0", "MIT")]);
        let cyclonedx = SbomDiffer::to_cyclonedx(&sbom);
        assert_eq!(cyclonedx.dependencies.len(), 1);
        assert_eq!(cyclonedx.dependencies[0].ref_, "app");
        assert_eq!(cyclonedx.dependencies[0].depends_on, vec!["lib"]);
    }
}
