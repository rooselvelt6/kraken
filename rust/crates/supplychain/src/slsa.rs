use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaProvenance {
    pub builder: SlsaBuilder,
    pub build_type: String,
    pub invocation: SlsaInvocation,
    pub materials: Vec<SlsaMaterial>,
    pub byproducts: Vec<SlsaByproduct>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaBuilder {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaInvocation {
    pub config_source: SlsaConfigSource,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaConfigSource {
    pub uri: String,
    pub digest: Option<String>,
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaMaterial {
    pub uri: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaByproduct {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaVerificationResult {
    pub level: SlsaLevel,
    pub proven: bool,
    pub checks: Vec<SlsaCheck>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlsaLevel {
    None,
    L1,
    L2,
    L3,
    L4,
}

impl PartialOrd for SlsaLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let rank = |l: &SlsaLevel| -> u8 {
            match l {
                SlsaLevel::None => 0,
                SlsaLevel::L1 => 1,
                SlsaLevel::L2 => 2,
                SlsaLevel::L3 => 3,
                SlsaLevel::L4 => 4,
            }
        };
        rank(self).partial_cmp(&rank(other))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaCheck {
    pub name: String,
    pub passed: bool,
    pub description: String,
}

pub struct SlsaVerifier;

impl Default for SlsaVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SlsaVerifier {
    pub fn new() -> Self {
        SlsaVerifier
    }

    pub fn verify(provenance: &SlsaProvenance, target_level: SlsaLevel) -> SlsaVerificationResult {
        let level = Self::detect_level(provenance);
        let checks = Self::run_checks(provenance, &target_level);
        let proven = level >= target_level;

        let mut details = Vec::new();
        details.push(format!("Detected SLSA level: {:?}", level));
        details.push(format!("Target SLSA level: {:?}", target_level));
        details.push(format!("Target met: {}", proven));

        SlsaVerificationResult {
            level,
            proven,
            checks,
            details,
        }
    }

    fn detect_level(provenance: &SlsaProvenance) -> SlsaLevel {
        let has_builder = !provenance.builder.id.is_empty();
        let has_materials = !provenance.materials.is_empty();
        let has_config = provenance.invocation.config_source.uri.len() > 5;
        let has_byproducts = !provenance.byproducts.is_empty();

        if has_builder && has_materials && has_config && has_byproducts {
            SlsaLevel::L3
        } else if has_builder && has_materials && has_config {
            SlsaLevel::L2
        } else if has_builder {
            SlsaLevel::L1
        } else {
            SlsaLevel::None
        }
    }

    fn run_checks(provenance: &SlsaProvenance, target: &SlsaLevel) -> Vec<SlsaCheck> {
        let mut checks = Vec::new();
        let level_order = |l: &SlsaLevel| -> u8 {
            match l {
                SlsaLevel::L1 => 1,
                SlsaLevel::L2 => 2,
                SlsaLevel::L3 => 3,
                SlsaLevel::L4 => 4,
                SlsaLevel::None => 0,
            }
        };
        let t = level_order(target);

        if t >= 1 {
            checks.push(SlsaCheck {
                name: "Builder ID present".to_string(),
                passed: !provenance.builder.id.is_empty(),
                description: format!("Builder: {}", provenance.builder.id),
            });
        }

        if t >= 2 {
            checks.push(SlsaCheck {
                name: "Materials present".to_string(),
                passed: !provenance.materials.is_empty(),
                description: format!("{} materials", provenance.materials.len()),
            });
            checks.push(SlsaCheck {
                name: "Config source present".to_string(),
                passed: provenance.invocation.config_source.uri.len() > 5,
                description: provenance.invocation.config_source.uri.clone(),
            });
        }

        if t >= 3 {
            checks.push(SlsaCheck {
                name: "Byproducts present".to_string(),
                passed: !provenance.byproducts.is_empty(),
                description: format!("{} byproducts", provenance.byproducts.len()),
            });
        }

        if t >= 4 {
            checks.push(SlsaCheck {
                name: "Reproducible build".to_string(),
                passed: false,
                description: "L4 requires reproducible builds".to_string(),
            });
        }

        checks
    }

    pub fn generate_provenance(builder_id: &str, repo_uri: &str, materials: &[(&str, &str)]) -> SlsaProvenance {
        SlsaProvenance {
            builder: SlsaBuilder { id: builder_id.to_string() },
            build_type: "https://slsa.dev/build-type/v1".to_string(),
            invocation: SlsaInvocation {
                config_source: SlsaConfigSource {
                    uri: repo_uri.to_string(),
                    digest: None,
                    entry_point: "build".to_string(),
                },
                parameters: vec![],
            },
            materials: materials.iter().map(|&(uri, digest)| SlsaMaterial {
                uri: uri.to_string(),
                digest: digest.to_string(),
            }).collect(),
            byproducts: vec![
                SlsaByproduct { name: "sha256".to_string(), value: "".to_string() },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_l3() {
        let prov = SlsaVerifier::generate_provenance(
            "https://github.com/example/builder",
            "https://github.com/example/repo",
            &[("source.tar.gz", "sha256:abc123")],
        );
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L3);
        assert!(result.proven);
    }

    #[test]
    fn test_verify_none() {
        let prov = SlsaProvenance {
            builder: SlsaBuilder { id: String::new() },
            build_type: String::new(),
            invocation: SlsaInvocation {
                config_source: SlsaConfigSource { uri: String::new(), digest: None, entry_point: String::new() },
                parameters: vec![],
            },
            materials: vec![],
            byproducts: vec![],
        };
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L1);
        assert!(!result.proven);
    }

    #[test]
    fn test_level_l1() {
        let prov = SlsaVerifier::generate_provenance("builder", "", &[]);
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L1);
        assert!(result.proven);
    }

    #[test]
    fn test_level_l2_fail() {
        let prov = SlsaVerifier::generate_provenance("builder", "", &[]);
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L2);
        assert!(!result.proven);
    }

    #[test]
    fn test_verification_serde() {
        let prov = SlsaVerifier::generate_provenance("test", "repo", &[]);
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L1);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("proven"));
    }

    #[test]
    fn test_level_ordering() {
        assert!(SlsaLevel::None < SlsaLevel::L1);
        assert!(SlsaLevel::L1 < SlsaLevel::L2);
        assert!(SlsaLevel::L2 < SlsaLevel::L3);
        assert!(SlsaLevel::L3 < SlsaLevel::L4);
    }

    #[test]
    fn test_level_equality() {
        assert_eq!(SlsaLevel::L1, SlsaLevel::L1);
        assert_ne!(SlsaLevel::L1, SlsaLevel::L2);
    }

    #[test]
    fn test_verify_l2_with_materials_and_config() {
        let prov = SlsaVerifier::generate_provenance(
            "builder-id",
            "https://github.com/example/repo",
            &[("src.tar.gz", "sha256:abc")],
        );
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L2);
        assert!(result.proven);
    }

    #[test]
    fn test_verify_l4_not_met() {
        let prov = SlsaVerifier::generate_provenance(
            "builder",
            "https://repo.example.com/build",
            &[("src.tar.gz", "sha256:abc")],
        );
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L4);
        assert!(!result.proven);
    }

    #[test]
    fn test_slsa_check_struct() {
        let check = SlsaCheck {
            name: "test".to_string(),
            passed: true,
            description: "desc".to_string(),
        };
        assert!(check.passed);
    }

    #[test]
    fn test_generate_provenance_materials() {
        let prov = SlsaVerifier::generate_provenance(
            "builder",
            "https://repo.example.com",
            &[("a.tar.gz", "sha256:aaa"), ("b.tar.gz", "sha256:bbb")],
        );
        assert_eq!(prov.materials.len(), 2);
        assert_eq!(prov.materials[0].uri, "a.tar.gz");
        assert_eq!(prov.materials[1].digest, "sha256:bbb");
    }

    #[test]
    fn test_generate_provenance_has_byproducts() {
        let prov = SlsaVerifier::generate_provenance("b", "r", &[]);
        assert_eq!(prov.byproducts.len(), 1);
        assert_eq!(prov.byproducts[0].name, "sha256");
    }

    #[test]
    fn test_verify_empty_builder_no_level() {
        let prov = SlsaProvenance {
            builder: SlsaBuilder { id: String::new() },
            build_type: String::new(),
            invocation: SlsaInvocation {
                config_source: SlsaConfigSource { uri: String::new(), digest: None, entry_point: String::new() },
                parameters: vec![],
            },
            materials: vec![],
            byproducts: vec![],
        };
        let result = SlsaVerifier::verify(&prov, SlsaLevel::None);
        assert!(result.proven);
    }

    #[test]
    fn test_slsa_verifier_default() {
        let v = SlsaVerifier::default();
        let prov = SlsaVerifier::generate_provenance("b", "r", &[]);
        let result = SlsaVerifier::verify(&prov, SlsaLevel::L1);
        assert!(result.proven);
    }

    #[test]
    fn test_slsa_provenance_serde() {
        let prov = SlsaVerifier::generate_provenance(
            "https://builder.example.com",
            "https://repo.example.com",
            &[("src.tar.gz", "sha256:abc123")],
        );
        let json = serde_json::to_string_pretty(&prov).unwrap();
        assert!(json.contains("builder"));
        assert!(json.contains("materials"));
    }
}
