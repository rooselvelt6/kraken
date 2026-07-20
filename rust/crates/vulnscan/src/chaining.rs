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
    /// Finds exploit chains by combining related vulnerabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::chaining::VulnerabilityChainer;
    /// use vulnscan::{Finding, Severity, DiscoveryMethod, ExploitType};
    /// use std::path::PathBuf;
    /// let r = Finding::new(Severity::High, "info leak read primitive",
    ///     Some(PathBuf::from("/kernel/vuln.c")), None, None, None,
    ///     Some("CWE-200".to_string()), 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let w = Finding::new(Severity::Critical, "heap overflow write primitive",
    ///     Some(PathBuf::from("/kernel/vuln.c")), None, None, None,
    ///     Some("CWE-787".to_string()), 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let chains = VulnerabilityChainer::find_chains(&[r, w]);
    /// assert!(!chains.is_empty());
    /// ```
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
                f.cwe.as_deref().is_some_and(|cwe| {
                    cwe.contains("200") || cwe.contains("203") || cwe.contains("402")
                }) && Self::is_kernel_path(f)
            })
            .collect();
        let kernel_mem_corruptions: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.cwe.as_deref().is_some_and(|cwe| {
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

        // Kernel: physmap / physical memory mapping + write primitive → kernel R/W
        let physmap_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                if !Self::is_kernel_path(f) {
                    return false;
                }
                let desc = f.description.to_lowercase();
                desc.contains("physical memory")
                    || desc.contains("/dev/mem")
                    || desc.contains("cma")
                    || desc.contains("dma")
                    || desc.contains("physmap")
                    || desc.contains("memory-mapped")
            })
            .collect();
        let write_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.cwe.as_deref().is_some_and(|cwe| {
                    cwe.contains("787") || cwe.contains("120") || cwe.contains("416")
                }) && Self::is_kernel_path(f)
            })
            .collect();
        for phys in &physmap_findings {
            for write in &write_findings {
                if phys.id != write.id {
                    chains.push(ChainedExploit {
                        id: crate::new_finding_id(),
                        findings: vec![(*phys).clone(), (*write).clone()],
                        chain_type: ChainType::PhysmapSpray,
                        description: format!(
                            "Physmap/physical memory mapping ({}) + write primitive ({}) → direct kernel memory write via physical mapping",
                            phys.cwe.as_deref().unwrap_or("unknown"),
                            write.cwe.as_deref().unwrap_or("unknown"),
                        ),
                        estimated_impact: Severity::Critical,
                    });
                }
            }
        }

        // Kernel: Dirty Pipe style — page cache overwrite via pipe/splice
        let pipe_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                if !Self::is_kernel_path(f) {
                    return false;
                }
                let desc = f.description.to_lowercase();
                desc.contains("pipe")
                    || desc.contains("splice")
                    || desc.contains("page_cache")
                    || desc.contains("flag")
            })
            .collect();
        let pipe_readwrite: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                if !Self::is_kernel_path(f) {
                    return false;
                }
                let desc = f.description.to_lowercase();
                (desc.contains("read") || desc.contains("write") || desc.contains("overwrite"))
                    && (desc.contains("read-only") || desc.contains("bypass") || desc.contains("flag"))
            })
            .collect();
        for pipe_f in &pipe_findings {
            for rw in &pipe_readwrite {
                if pipe_f.id != rw.id {
                    chains.push(ChainedExploit {
                        id: crate::new_finding_id(),
                        findings: vec![(*pipe_f).clone(), (*rw).clone()],
                        chain_type: ChainType::DirtyPipeStyle,
                        description: format!(
                            "Pipe/splice page cache finding ({}) + read/write bypass ({}) → Dirty Pipe style overwrite of read-only mappings",
                            pipe_f.description.chars().take(80).collect::<String>(),
                            rw.description.chars().take(80).collect::<String>(),
                        ),
                        estimated_impact: Severity::Critical,
                    });
                }
            }
        }
        // Also detect standalone read-only bypass or overwrite in pipe-like kernel paths
        let overwrite_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                if !Self::is_kernel_path(f) {
                    return false;
                }
                let desc = f.description.to_lowercase();
                (desc.contains("read-only") || desc.contains("overwrite"))
                    && (desc.contains("bypass") || desc.contains("pipe") || desc.contains("page"))
            })
            .collect();
        for ow in &overwrite_findings {
            if !pipe_findings.iter().any(|p| p.id == ow.id) {
                chains.push(ChainedExploit {
                    id: crate::new_finding_id(),
                    findings: vec![(*ow).clone()],
                    chain_type: ChainType::DirtyPipeStyle,
                    description: format!(
                        "Read-only bypass / overwrite at {} — potential Dirty Pipe style vulnerability",
                        ow.file_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                    ),
                    estimated_impact: Severity::Critical,
                });
            }
        }

        chains
    }

    fn is_kernel_path(f: &Finding) -> bool {
        f.file_path.as_ref().is_some_and(|p| {
            let s = p.to_string_lossy();
            s.contains("/kernel/") || s.contains("/drivers/") || s.contains("/arch/")
                || s.contains("/fs/") || s.contains("/net/") || s.contains("/include/linux/")
        })
    }

    /// Chains read and write bugs in the same file into a Read+Write exploit chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::chaining::VulnerabilityChainer;
    /// use vulnscan::{Finding, Severity, DiscoveryMethod};
    /// use std::path::PathBuf;
    /// let r = Finding::new(Severity::High, "read bug", Some(PathBuf::from("a.c")), None, None, None, None, 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let w = Finding::new(Severity::Critical, "write bug", Some(PathBuf::from("a.c")), None, None, None, None, 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let chains = VulnerabilityChainer::chain_read_write(&[r], &[w]);
    /// assert_eq!(chains.len(), 1);
    /// ```
    pub fn chain_read_write(read_bugs: &[Finding], write_bugs: &[Finding]) -> Vec<ChainedExploit> {
        let mut chains = Vec::new();
        for read_bug in read_bugs {
            for write_bug in write_bugs {
                if read_bug.file_path == write_bug.file_path {
                    chains.push(ChainedExploit {
                        id: crate::new_finding_id(),
                        findings: vec![read_bug.clone(), write_bug.clone()],
                        chain_type: ChainType::ReadPlusWrite,
                        description: "Read primitive + write primitive in same component → full control".to_string(),
                        estimated_impact: Severity::Critical,
                    });
                }
            }
        }
        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoveryMethod, Finding};
    use std::path::PathBuf;

    #[test]
    fn physmap_spray_chain_detected() {
        let physmap = Finding::new(
            Severity::High,
            "physical memory mapping via CMA allows user access",
            Some(PathBuf::from("/kernel/drivers/gpu/drm.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.8,
            DiscoveryMethod::StaticPatternMatching,
        );
        let write = Finding::new(
            Severity::Critical,
            "heap overflow write primitive",
            Some(PathBuf::from("/kernel/drivers/gpu/drm.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.9,
            DiscoveryMethod::StaticPatternMatching,
        );
        let chains = VulnerabilityChainer::find_chains(&[physmap, write]);
        assert!(
            chains.iter().any(|c| c.chain_type == ChainType::PhysmapSpray),
            "expected PhysmapSpray chain, got: {:?}",
            chains.iter().map(|c| &c.chain_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn physmap_dev_mem_detected() {
        let devmem = Finding::new(
            Severity::High,
            "user can mmap /dev/mem to access kernel memory",
            Some(PathBuf::from("/kernel/drivers/char/mem.c")),
            None,
            None,
            None,
            Some("CWE-120".to_string()),
            0.7,
            DiscoveryMethod::StaticPatternMatching,
        );
        let overflow = Finding::new(
            Severity::Critical,
            "DMA buffer overflow allows controlled write",
            Some(PathBuf::from("/kernel/drivers/char/mem.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.85,
            DiscoveryMethod::StaticPatternMatching,
        );
        let chains = VulnerabilityChainer::find_chains(&[devmem, overflow]);
        assert!(chains.iter().any(|c| c.chain_type == ChainType::PhysmapSpray));
    }

    #[test]
    fn physmap_no_match_non_kernel() {
        let physmap = Finding::new(
            Severity::High,
            "physical memory mapping via CMA",
            Some(PathBuf::from("/home/user/app/mem.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.8,
            DiscoveryMethod::StaticPatternMatching,
        );
        let write = Finding::new(
            Severity::Critical,
            "heap overflow write primitive",
            Some(PathBuf::from("/home/user/app/mem.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.9,
            DiscoveryMethod::StaticPatternMatching,
        );
        let chains = VulnerabilityChainer::find_chains(&[physmap, write]);
        assert!(!chains.iter().any(|c| c.chain_type == ChainType::PhysmapSpray));
    }

    #[test]
    fn dirty_pipe_style_chain_detected() {
        let pipe = Finding::new(
            Severity::High,
            "pipe splice operation lacks proper page_cache flag validation",
            Some(PathBuf::from("/kernel/fs/pipe.c")),
            None,
            None,
            None,
            Some("CWE-20".to_string()),
            0.8,
            DiscoveryMethod::StaticPatternMatching,
        );
        let bypass = Finding::new(
            Severity::Critical,
            "read-only bypass allows overwrite of page cache",
            Some(PathBuf::from("/kernel/fs/pipe.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.9,
            DiscoveryMethod::StaticPatternMatching,
        );
        let chains = VulnerabilityChainer::find_chains(&[pipe, bypass]);
        assert!(
            chains.iter().any(|c| c.chain_type == ChainType::DirtyPipeStyle),
            "expected DirtyPipeStyle chain, got: {:?}",
            chains.iter().map(|c| &c.chain_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn dirty_pipe_standalone_overwrite_detected() {
        let overwrite = Finding::new(
            Severity::Critical,
            "read-only bypass allows overwrite of read-only mapped pages",
            Some(PathBuf::from("/kernel/mm/mmap.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.85,
            DiscoveryMethod::StaticPatternMatching,
        );
        let chains = VulnerabilityChainer::find_chains(&[overwrite]);
        assert!(
            chains.iter().any(|c| c.chain_type == ChainType::DirtyPipeStyle),
            "expected standalone DirtyPipeStyle chain"
        );
    }

    #[test]
    fn dirty_pipe_no_match_non_kernel() {
        let pipe = Finding::new(
            Severity::High,
            "pipe splice lacks flag validation",
            Some(PathBuf::from("/home/user/pipe.c")),
            None,
            None,
            None,
            Some("CWE-20".to_string()),
            0.8,
            DiscoveryMethod::StaticPatternMatching,
        );
        let bypass = Finding::new(
            Severity::Critical,
            "read-only bypass allows overwrite",
            Some(PathBuf::from("/home/user/pipe.c")),
            None,
            None,
            None,
            Some("CWE-787".to_string()),
            0.9,
            DiscoveryMethod::StaticPatternMatching,
        );
        let chains = VulnerabilityChainer::find_chains(&[pipe, bypass]);
        assert!(!chains.iter().any(|c| c.chain_type == ChainType::DirtyPipeStyle));
    }
}
