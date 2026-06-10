use crate::{Finding, Severity};

#[derive(Debug, Clone)]
pub struct ChainedExploit {
    pub id: String,
    pub findings: Vec<Finding>,
    pub chain_type: ChainType,
    pub description: String,
    pub estimated_impact: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    KaslrBypassPlusWrite,
    ReadPlusWrite,
    UseAfterFreePlusSpray,
    MultipleVulnerabilities,
}

pub struct VulnerabilityChainer;

impl VulnerabilityChainer {
    pub fn find_chains(findings: &[Finding]) -> Vec<ChainedExploit> {
        let mut chains = Vec::new();

        let _critical: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        let _high: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();

        // KASLR bypass + write primitive → privilege escalation chain
        let read_bugs: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.description.contains("read") || f.description.contains("information disclosure")
            })
            .collect();
        let write_bugs: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.description.contains("write") || f.description.contains("overflow"))
            .collect();

        for read_bug in &read_bugs {
            for write_bug in &write_bugs {
                if read_bug.file_path == write_bug.file_path && read_bug.id != write_bug.id {
                    chains.push(ChainedExploit {
                        id: crate::new_finding_id(),
                        findings: vec![(*read_bug).clone(), (*write_bug).clone()],
                        chain_type: ChainType::KaslrBypassPlusWrite,
                        description: format!(
                            "Chain: KASLR bypass ({}) + write primitive ({}) → privilege escalation",
                            read_bug.cwe.as_deref().unwrap_or("unknown"),
                            write_bug.cwe.as_deref().unwrap_or("unknown"),
                        ),
                        estimated_impact: Severity::Critical,
                    });
                }
            }
        }

        // Use-after-free + heap spray
        let uaf_bugs: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.cwe.as_deref() == Some("CWE-416"))
            .collect();
        for uaf in &uaf_bugs {
            chains.push(ChainedExploit {
                id: crate::new_finding_id(),
                findings: vec![(*uaf).clone()],
                chain_type: ChainType::UseAfterFreePlusSpray,
                description: format!(
                    "Use-after-free at {} requires heap spray for exploitation",
                    uaf.file_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ),
                estimated_impact: Severity::High,
            });
        }

        chains
    }

    pub fn chain_read_write(read_bugs: &[Finding], write_bugs: &[Finding]) -> Vec<ChainedExploit> {
        let mut chains = Vec::new();
        for read_bug in read_bugs {
            for write_bug in write_bugs {
                if read_bug.file_path == write_bug.file_path {
                    chains.push(ChainedExploit {
                        id: crate::new_finding_id(),
                        findings: vec![read_bug.clone(), write_bug.clone()],
                        chain_type: ChainType::ReadPlusWrite,
                        description: format!(
                            "Read primitive + write primitive in same component → full control"
                        ),
                        estimated_impact: Severity::Critical,
                    });
                }
            }
        }
        chains
    }
}
