use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisBenchmark {
    pub target: String,
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub checks: Vec<CisCheck>,
    pub compliance_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisCheck {
    pub id: String,
    pub name: String,
    pub description: String,
    pub level: u8,
    pub status: CheckResult,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckResult {
    Pass,
    Fail,
    Na,
}

pub struct CisScanner;

impl Default for CisScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CisScanner {
    pub fn new() -> Self {
        CisScanner
    }

    pub fn scan_docker(host_config: &str) -> CisBenchmark {
        Self::run_benchmark("Docker", host_config, Self::docker_checks())
    }

    pub fn scan_kubernetes(kube_config: &str) -> CisBenchmark {
        Self::run_benchmark("Kubernetes", kube_config, Self::kubernetes_checks())
    }

    pub fn scan_linux(sysctl: &str) -> CisBenchmark {
        Self::run_benchmark("Linux", sysctl, Self::linux_checks())
    }

    fn run_benchmark(target: &str, config: &str, checks: Vec<CisTemplate>) -> CisBenchmark {
        let mut results = Vec::new();
        for check in &checks {
            let status = Self::evaluate(check, config);
            results.push(CisCheck {
                id: check.id.clone(),
                name: check.name.clone(),
                description: check.description.clone(),
                level: check.level,
                status,
                remediation: check.remediation.clone(),
            });
        }

        let total = results.len();
        let passed = results.iter().filter(|c| c.status == CheckResult::Pass).count();
        let failed = results.iter().filter(|c| c.status == CheckResult::Fail).count();
        let na = results.iter().filter(|c| c.status == CheckResult::Na).count();
        let compliance = if total > na {
            passed as f64 / (total - na) as f64 * 100.0
        } else {
            0.0
        };

        CisBenchmark {
            target: target.to_string(),
            total_checks: total,
            passed,
            failed,
            not_applicable: na,
            checks: results,
            compliance_pct: compliance,
        }
    }

    fn evaluate(check: &CisTemplate, config: &str) -> CheckResult {
        let cfg = config.to_lowercase();
        match check.id.as_str() {
            "D-1" | "D-2" | "D-3" => {
                if check.pass_pattern.iter().all(|p| cfg.contains(p)) {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "K-1" | "K-3" => {
                if cfg.contains("readonlyrootfilesystem: true") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "K-2" => {
                if cfg.contains("privileged: false") || !cfg.contains("privileged:") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "K-4" => {
                if cfg.contains("automountserviceaccounttoken: false") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-1" => {
                if cfg.contains("kernel.randomize_va_space = 2") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-2" => {
                if cfg.contains("net.ipv4.conf.all.rp_filter = 1") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-3" => {
                if cfg.contains("net.ipv4.tcp_syncookies = 1") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            _ => CheckResult::Na,
        }
    }

    fn docker_checks() -> Vec<CisTemplate> {
        vec![
            CisTemplate {
                id: "D-1".to_string(),
                name: "Ensure container hostname is set".to_string(),
                description: "Running containers should have a hostname".to_string(),
                level: 1,
                pass_pattern: vec!["hostname".to_string()],
                remediation: "Use --hostname flag".to_string(),
            },
            CisTemplate {
                id: "D-2".to_string(),
                name: "Ensure containers run with read-only root filesystem".to_string(),
                description: "Containers should use read-only rootfs".to_string(),
                level: 1,
                pass_pattern: vec!["read-only".to_string()],
                remediation: "Use --read-only flag".to_string(),
            },
            CisTemplate {
                id: "D-3".to_string(),
                name: "Ensure Docker socket is not mounted".to_string(),
                description: "Docker socket should not be mounted in containers".to_string(),
                level: 1,
                pass_pattern: vec!["/var/run/docker.sock".to_string()],
                remediation: "Do not mount /var/run/docker.sock".to_string(),
            },
        ]
    }

    fn kubernetes_checks() -> Vec<CisTemplate> {
        vec![
            CisTemplate {
                id: "K-1".to_string(),
                name: "Ensure containers run as non-root".to_string(),
                description: "Containers should not run as root".to_string(),
                level: 1,
                pass_pattern: vec!["runAsNonRoot: true".to_string()],
                remediation: "Set securityContext.runAsNonRoot: true".to_string(),
            },
            CisTemplate {
                id: "K-2".to_string(),
                name: "Ensure containers are not privileged".to_string(),
                description: "Privileged containers should not be allowed".to_string(),
                level: 1,
                pass_pattern: vec![],
                remediation: "Set securityContext.privileged: false".to_string(),
            },
            CisTemplate {
                id: "K-3".to_string(),
                name: "Ensure containers have read-only root filesystem".to_string(),
                description: "Root filesystem should be read-only".to_string(),
                level: 2,
                pass_pattern: vec!["readOnlyRootFilesystem: true".to_string()],
                remediation: "Set securityContext.readOnlyRootFilesystem: true".to_string(),
            },
            CisTemplate {
                id: "K-4".to_string(),
                name: "Ensure ServiceAccount token is not automatically mounted".to_string(),
                description: "Auto-mounting of SA tokens should be disabled".to_string(),
                level: 1,
                pass_pattern: vec![],
                remediation: "Set automountServiceAccountToken: false".to_string(),
            },
        ]
    }

    fn linux_checks() -> Vec<CisTemplate> {
        vec![
            CisTemplate {
                id: "L-1".to_string(),
                name: "Ensure ASLR is enabled".to_string(),
                description: "Address Space Layout Randomization should be enabled".to_string(),
                level: 1,
                pass_pattern: vec!["kernel.randomize_va_space = 2".to_string()],
                remediation: "Set kernel.randomize_va_space = 2 in sysctl".to_string(),
            },
            CisTemplate {
                id: "L-2".to_string(),
                name: "Ensure source route validation is enabled".to_string(),
                description: "Reverse path filtering should be enabled".to_string(),
                level: 1,
                pass_pattern: vec!["net.ipv4.conf.all.rp_filter = 1".to_string()],
                remediation: "Set net.ipv4.conf.all.rp_filter = 1".to_string(),
            },
            CisTemplate {
                id: "L-3".to_string(),
                name: "Ensure TCP SYN cookies are enabled".to_string(),
                description: "SYN cookies protect against SYN flood attacks".to_string(),
                level: 1,
                pass_pattern: vec!["net.ipv4.tcp_syncookies = 1".to_string()],
                remediation: "Set net.ipv4.tcp_syncookies = 1".to_string(),
            },
        ]
    }
}

struct CisTemplate {
    id: String,
    name: String,
    description: String,
    level: u8,
    pass_pattern: Vec<String>,
    remediation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_scan() {
        let result = CisScanner::scan_docker("");
        assert_eq!(result.target, "Docker");
        assert!(result.total_checks > 0);
    }

    #[test]
    fn test_kubernetes_scan() {
        let result = CisScanner::scan_kubernetes("readOnlyRootFilesystem: true");
        assert!(result.checks.iter().any(|c| c.id == "K-3" && c.status == CheckResult::Pass));
    }

    #[test]
    fn test_linux_scan_passing() {
        let sysctl = "kernel.randomize_va_space = 2\nnet.ipv4.conf.all.rp_filter = 1";
        let result = CisScanner::scan_linux(sysctl);
        assert!(result.passed >= 2);
    }

    #[test]
    fn test_linux_scan_failing() {
        let result = CisScanner::scan_linux("");
        assert!(result.failed > 0);
    }

    #[test]
    fn test_cis_benchmark_serde() {
        let result = CisScanner::scan_docker("test");
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("Docker"));
    }
}
