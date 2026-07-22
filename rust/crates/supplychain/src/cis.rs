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
            "D-1" | "D-2" | "D-3" | "D-4" | "D-5" | "D-6" | "D-7" | "D-8" => {
                if check.pass_pattern.is_empty() {
                    if cfg.contains("privileged: true") {
                        CheckResult::Fail
                    } else {
                        CheckResult::Pass
                    }
                } else if check.pass_pattern.iter().all(|p| cfg.contains(p)) {
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
            "K-5" | "K-6" => {
                if cfg.contains("limits:") || cfg.contains("requests:") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "K-7" | "K-8" => {
                if cfg.contains("livenessprobe:") || cfg.contains("readinessprobe:") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "K-9" => {
                if cfg.contains("drop:") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "K-10" => {
                if cfg.contains("seccompprofile:") {
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
            "L-4" => {
                if cfg.contains("net.ipv4.conf.all.accept_redirects = 0") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-5" => {
                if cfg.contains("net.ipv4.conf.all.accept_source_route = 0") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-6" => {
                if cfg.contains("net.ipv4.tcp_timestamps = 1") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-7" => {
                if cfg.contains("net.ipv6.conf.all.accept_ra = 0") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-8" => {
                if cfg.contains("net.ipv6.conf.all.disable_ipv6 = 1") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-9" => {
                if cfg.contains("fs.suid_dumpable = 0") {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
            "L-10" => {
                if cfg.contains("net.ipv4.ip_forward = 0") {
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
            CisTemplate {
                id: "D-4".to_string(),
                name: "Ensure containers do not run as root".to_string(),
                description: "Containers should run as non-root user".to_string(),
                level: 1,
                pass_pattern: vec!["user:".to_string()],
                remediation: "Use USER directive in Dockerfile or --user flag".to_string(),
            },
            CisTemplate {
                id: "D-5".to_string(),
                name: "Ensure memory limit is set".to_string(),
                description: "Containers should have memory limits".to_string(),
                level: 2,
                pass_pattern: vec!["memory".to_string()],
                remediation: "Use --memory flag or resource limits".to_string(),
            },
            CisTemplate {
                id: "D-6".to_string(),
                name: "Ensure CPU limit is set".to_string(),
                description: "Containers should have CPU limits".to_string(),
                level: 2,
                pass_pattern: vec!["cpus".to_string()],
                remediation: "Use --cpus flag or resource limits".to_string(),
            },
            CisTemplate {
                id: "D-7".to_string(),
                name: "Ensure privileged mode is not used".to_string(),
                description: "Containers should not run in privileged mode".to_string(),
                level: 1,
                pass_pattern: vec![],
                remediation: "Do not use --privileged flag".to_string(),
            },
            CisTemplate {
                id: "D-8".to_string(),
                name: "Ensure health check is configured".to_string(),
                description: "Containers should have health checks".to_string(),
                level: 2,
                pass_pattern: vec!["healthcheck".to_string()],
                remediation: "Add HEALTHCHECK instruction in Dockerfile".to_string(),
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
            CisTemplate {
                id: "K-5".to_string(),
                name: "Ensure containers have resource limits".to_string(),
                description: "Containers should have CPU and memory limits".to_string(),
                level: 1,
                pass_pattern: vec!["limits:".to_string()],
                remediation: "Set resources.limits in container spec".to_string(),
            },
            CisTemplate {
                id: "K-6".to_string(),
                name: "Ensure containers have resource requests".to_string(),
                description: "Containers should have CPU and memory requests".to_string(),
                level: 2,
                pass_pattern: vec!["requests:".to_string()],
                remediation: "Set resources.requests in container spec".to_string(),
            },
            CisTemplate {
                id: "K-7".to_string(),
                name: "Ensure liveness probe is configured".to_string(),
                description: "Containers should have liveness probes".to_string(),
                level: 2,
                pass_pattern: vec!["livenessProbe:".to_string()],
                remediation: "Add livenessProbe to container spec".to_string(),
            },
            CisTemplate {
                id: "K-8".to_string(),
                name: "Ensure readiness probe is configured".to_string(),
                description: "Containers should have readiness probes".to_string(),
                level: 2,
                pass_pattern: vec!["readinessProbe:".to_string()],
                remediation: "Add readinessProbe to container spec".to_string(),
            },
            CisTemplate {
                id: "K-9".to_string(),
                name: "Ensure capabilities are dropped".to_string(),
                description: "Containers should drop unnecessary capabilities".to_string(),
                level: 1,
                pass_pattern: vec!["drop:".to_string()],
                remediation: "Add securityContext.capabilities.drop in container spec".to_string(),
            },
            CisTemplate {
                id: "K-10".to_string(),
                name: "Ensure seccomp profile is set".to_string(),
                description: "Containers should use seccomp profiles".to_string(),
                level: 2,
                pass_pattern: vec!["seccompProfile:".to_string()],
                remediation: "Set securityContext.seccompProfile in container spec".to_string(),
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
            CisTemplate {
                id: "L-4".to_string(),
                name: "Ensure ICMP redirect acceptance is disabled".to_string(),
                description: "ICMP redirects should not be accepted".to_string(),
                level: 1,
                pass_pattern: vec!["net.ipv4.conf.all.accept_redirects = 0".to_string()],
                remediation: "Set net.ipv4.conf.all.accept_redirects = 0".to_string(),
            },
            CisTemplate {
                id: "L-5".to_string(),
                name: "Ensure source routed packets are rejected".to_string(),
                description: "Source routed packets should be rejected".to_string(),
                level: 1,
                pass_pattern: vec!["net.ipv4.conf.all.accept_source_route = 0".to_string()],
                remediation: "Set net.ipv4.conf.all.accept_source_route = 0".to_string(),
            },
            CisTemplate {
                id: "L-6".to_string(),
                name: "Ensure TCP timestamps are enabled".to_string(),
                description: "TCP timestamps help protect against wrapped sequence numbers".to_string(),
                level: 2,
                pass_pattern: vec!["net.ipv4.tcp_timestamps = 1".to_string()],
                remediation: "Set net.ipv4.tcp_timestamps = 1".to_string(),
            },
            CisTemplate {
                id: "L-7".to_string(),
                name: "Ensure IPv6 router advertisements are not accepted".to_string(),
                description: "IPv6 router advertisements should not be accepted".to_string(),
                level: 1,
                pass_pattern: vec!["net.ipv6.conf.all.accept_ra = 0".to_string()],
                remediation: "Set net.ipv6.conf.all.accept_ra = 0".to_string(),
            },
            CisTemplate {
                id: "L-8".to_string(),
                name: "Ensure IPv6 is disabled if not needed".to_string(),
                description: "IPv6 should be disabled if not required".to_string(),
                level: 2,
                pass_pattern: vec!["net.ipv6.conf.all.disable_ipv6 = 1".to_string()],
                remediation: "Set net.ipv6.conf.all.disable_ipv6 = 1".to_string(),
            },
            CisTemplate {
                id: "L-9".to_string(),
                name: "Ensure core dumps are restricted".to_string(),
                description: "Core dumps should be restricted for security".to_string(),
                level: 1,
                pass_pattern: vec!["fs.suid_dumpable = 0".to_string()],
                remediation: "Set fs.suid_dumpable = 0".to_string(),
            },
            CisTemplate {
                id: "L-10".to_string(),
                name: "Ensure IP forwarding is disabled".to_string(),
                description: "IP forwarding should be disabled on non-routers".to_string(),
                level: 1,
                pass_pattern: vec!["net.ipv4.ip_forward = 0".to_string()],
                remediation: "Set net.ipv4.ip_forward = 0".to_string(),
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

    #[test]
    fn test_docker_new_checks() {
        let result = CisScanner::scan_docker("user: nobody");
        assert!(result.total_checks >= 8);
        let user_check = result.checks.iter().find(|c| c.id == "D-4");
        assert!(user_check.is_some());
        assert_eq!(user_check.unwrap().status, CheckResult::Pass);
    }

    #[test]
    fn test_kubernetes_new_checks() {
        let config = "resources:\n  limits:\n    cpu: 100m\n  requests:\n    cpu: 50m\nlivenessProbe:\n  httpGet:\n    path: /\nreadinessProbe:\n  httpGet:\n    path: /\ncapabilities:\n  drop:\n    - ALL\nseccompProfile:\n  type: RuntimeDefault";
        let result = CisScanner::scan_kubernetes(config);
        assert!(result.total_checks >= 10);
        assert!(result.passed >= 5);
    }

    #[test]
    fn test_linux_new_checks() {
        let sysctl = "kernel.randomize_va_space = 2\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.tcp_timestamps = 1\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.all.disable_ipv6 = 1\nfs.suid_dumpable = 0\nnet.ipv4.ip_forward = 0";
        let result = CisScanner::scan_linux(sysctl);
        assert!(result.total_checks >= 10);
        assert!(result.passed >= 8);
    }

    #[test]
    fn test_linux_critical_checks() {
        let sysctl = "kernel.randomize_va_space = 2\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_ra = 0\nfs.suid_dumpable = 0\nnet.ipv4.ip_forward = 0";
        let result = CisScanner::scan_linux(sysctl);
        let critical_checks: Vec<_> = result.checks.iter().filter(|c| c.level == 1).collect();
        let passed_critical = critical_checks.iter().filter(|c| c.status == CheckResult::Pass).count();
        assert!(passed_critical >= 4);
    }

    #[test]
    fn test_compliance_percentage() {
        let result = CisScanner::scan_linux("kernel.randomize_va_space = 2");
        assert!(result.compliance_pct > 0.0);
        assert!(result.compliance_pct <= 100.0);
    }

    #[test]
    fn test_check_result_enum() {
        assert_eq!(CheckResult::Pass, CheckResult::Pass);
        assert_ne!(CheckResult::Pass, CheckResult::Fail);
        assert_ne!(CheckResult::Pass, CheckResult::Na);
    }
}
