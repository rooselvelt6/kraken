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
    InfoLeakChain,
    PhysmapSpray,
    DirtyPipeStyle,
    BPFChain,
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

        // Kernel: info leak + memory corruption → privesc
        let kernel_info_leaks: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.cwe.as_deref().map_or(false, |cwe| {
                    cwe.contains("200") || cwe.contains("203") || cwe.contains("402")
                }) && Self::is_kernel_path(f)
            })
            .collect();
        let kernel_mem_corruptions: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.cwe.as_deref().map_or(false, |cwe| {
                    cwe.contains("416") || cwe.contains("787") || cwe.contains("120")
                }) && Self::is_kernel_path(f)
            })
            .collect();
        for leak in &kernel_info_leaks {
            for mem in &kernel_mem_corruptions {
                if leak.id != mem.id {
                    chains.push(ChainedExploit {
                        id: crate::new_finding_id(),
                        findings: vec![(*leak).clone(), (*mem).clone()],
                        chain_type: ChainType::InfoLeakChain,
                        description: format!(
                            "Kernel info leak ({}) + memory corruption ({}) → KASLR bypass + privesc",
                            leak.cwe.as_deref().unwrap_or("unknown"),
                            mem.cwe.as_deref().unwrap_or("unknown"),
                        ),
                        estimated_impact: Severity::Critical,
                    });
                }
            }
        }

        // Kernel: BPF-related findings
        let bpf_bugs: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let desc = f.description.to_lowercase();
                (desc.contains("bpf") || desc.contains("ebpf") || desc.contains("berkeley packet"))
                    && Self::is_kernel_path(f)
            })
            .collect();
        for bpf in &bpf_bugs {
            chains.push(ChainedExploit {
                id: crate::new_finding_id(),
                findings: vec![(*bpf).clone()],
                chain_type: ChainType::BPFChain,
                description: format!(
                    "BPF vulnerability at {} — possible kernel memory read/write via crafted eBPF program",
                    bpf.file_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ),
                estimated_impact: Severity::Critical,
            });
        }

        chains
    }

    fn is_kernel_path(f: &Finding) -> bool {
        f.file_path.as_ref().map_or(false, |p| {
            let s = p.to_string_lossy();
            s.contains("/kernel/") || s.contains("/drivers/") || s.contains("/arch/")
                || s.contains("/fs/") || s.contains("/net/") || s.contains("/include/linux/")
        })
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
