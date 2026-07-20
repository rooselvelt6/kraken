

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerContainer {
    pub id: String,
    pub image: String,
    pub name: String,
    pub status: String,
    pub ports: Vec<String>,
    pub privileged: bool,
    pub host_network: bool,
    pub mounts: Vec<String>,
    pub env: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub container: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerAuditResult {
    pub containers: Vec<DockerContainer>,
    pub findings: Vec<DockerFinding>,
    pub total_containers: usize,
    pub privileged_containers: usize,
    pub exposed_host_ports: Vec<u16>,
}

pub struct DockerAuditor;

impl Default for DockerAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerAuditor {
    pub fn new() -> Self {
        DockerAuditor
    }

    pub fn audit_containers(containers: &[DockerContainer]) -> DockerAuditResult {
        let total_containers = containers.len();
        let privileged_containers = containers.iter().filter(|c| c.privileged).count();
        let mut exposed_host_ports = Vec::new();
        let mut findings = Vec::new();

        for c in containers {
            if c.privileged {
                findings.push(DockerFinding {
                    severity: "CRITICAL".to_string(),
                    category: "Privileged Container".to_string(),
                    description: format!("Container {} runs in privileged mode", c.name),
                    container: c.id.clone(),
                    recommendation: "Avoid --privileged, use --cap-add for specific capabilities".to_string(),
                });
            }
            if c.host_network {
                findings.push(DockerFinding {
                    severity: "HIGH".to_string(),
                    category: "Host Network".to_string(),
                    description: format!("Container {} uses host network", c.name),
                    container: c.id.clone(),
                    recommendation: "Use Docker bridge or overlay networks".to_string(),
                });
            }
            for port in &c.ports {
                if let Some((host_port, _)) = port.split_once("->") {
                    if let Ok(p) = host_port.trim().parse::<u16>() {
                        exposed_host_ports.push(p);
                        if p < 1024 {
                            findings.push(DockerFinding {
                                severity: "MEDIUM".to_string(),
                                category: "Privileged Port".to_string(),
                                description: format!("Container {} exposes privileged port {}", c.name, p),
                                container: c.id.clone(),
                                recommendation: "Use port mapping above 1024 if possible".to_string(),
                            });
                        }
                    }
                }
            }
            if c.image.contains(":latest") || !c.image.contains(':') {
                findings.push(DockerFinding {
                    severity: "LOW".to_string(),
                    category: "Image Tag".to_string(),
                    description: format!("Container {} uses tag 'latest' for {}", c.name, c.image),
                    container: c.id.clone(),
                    recommendation: "Pin to a specific version tag".to_string(),
                });
            }
        }

        exposed_host_ports.sort();
        exposed_host_ports.dedup();

        DockerAuditResult {
            containers: containers.to_vec(),
            findings,
            total_containers,
            privileged_containers,
            exposed_host_ports,
        }
    }

    pub fn check_dockerfile(dockerfile: &str) -> Vec<String> {
        let mut issues = Vec::new();
        for line in dockerfile.lines() {
            let trimmed = line.trim();
            if trimmed.to_lowercase().starts_with("add ") && !trimmed.contains("--chown=") {
                issues.push(format!("ADD without --chown: {}", trimmed));
            }
            if trimmed.to_lowercase().starts_with("user root") {
                issues.push("RUN as root user".to_string());
            }
            if !trimmed.to_lowercase().contains("apt-get") && trimmed.contains("rm -rf /var/lib/apt") {
                issues.push("apt cleanup without matching apt-get install in same layer".to_string());
            }
        }
        if !dockerfile.to_lowercase().contains("user") && !dockerfile.to_lowercase().contains("--chown") {
            issues.push("No USER directive found, container runs as root".to_string());
        }
        if !dockerfile.contains("EXPOSE") {
            issues.push("No EXPOSE directive found".to_string());
        }
        if !dockerfile.contains("HEALTHCHECK") {
            issues.push("No HEALTHCHECK instruction found".to_string());
        }
        issues
    }

    pub fn parse_docker_ps(output: &str) -> Vec<DockerContainer> {
        let mut containers = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let id = parts[0].to_string();
                let image = parts[1].to_string();
                let status_idx = parts.len() - 2;
                let status = parts[status_idx..].join(" ");
                containers.push(DockerContainer {
                    id,
                    image,
                    name: parts.last().unwrap_or(&"?").to_string(),
                    status,
                    ports: vec![],
                    privileged: false,
                    host_network: false,
                    mounts: vec![],
                    env: vec![],
                });
            }
        }
        containers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_privileged() {
        let containers = vec![DockerContainer {
            id: "abc123".to_string(),
            image: "nginx:latest".to_string(),
            name: "web".to_string(),
            status: "running".to_string(),
            ports: vec!["80->80/tcp".to_string()],
            privileged: true,
            host_network: false,
            mounts: vec![],
            env: vec![],
        }];
        let result = DockerAuditor::audit_containers(&containers);
        assert!(result.privileged_containers > 0);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_check_dockerfile() {
        let df = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y nginx && rm -rf /var/lib/apt/lists/*\nEXPOSE 80\nCMD [\"nginx\", \"-g\", \"daemon off;\"]\n";
        let issues = DockerAuditor::check_dockerfile(df);
        assert!(issues.iter().any(|i| i.contains("USER") || i.contains("HEALTHCHECK")));
    }

    #[test]
    fn test_parse_docker_ps() {
        let output = "abc123 nginx:latest  Up 2 hours  80->80/tcp  web";
        let containers = DockerAuditor::parse_docker_ps(output);
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].image, "nginx:latest");
    }

    #[test]
    fn test_audit_safe_container() {
        let containers = vec![DockerContainer {
            id: "def456".to_string(),
            image: "nginx:1.25".to_string(),
            name: "web".to_string(),
            status: "running".to_string(),
            ports: vec![],
            privileged: false,
            host_network: false,
            mounts: vec![],
            env: vec![],
        }];
        let result = DockerAuditor::audit_containers(&containers);
        assert_eq!(result.privileged_containers, 0);
    }

    #[test]
    fn test_docker_finding() {
        let f = DockerFinding {
            severity: "HIGH".to_string(),
            category: "test".to_string(),
            description: "desc".to_string(),
            container: "abc".to_string(),
            recommendation: "fix".to_string(),
        };
        let json = serde_json::to_string_pretty(&f).unwrap();
        assert!(json.contains("HIGH"));
    }

    #[test]
    fn test_audit_host_network() {
        let containers = vec![DockerContainer {
            id: "hn1".to_string(),
            image: "nginx:1.25".to_string(),
            name: "web".to_string(),
            status: "running".to_string(),
            ports: vec![],
            privileged: false,
            host_network: true,
            mounts: vec![],
            env: vec![],
        }];
        let result = DockerAuditor::audit_containers(&containers);
        assert!(result.findings.iter().any(|f| f.category == "Host Network"));
    }

    #[test]
    fn test_audit_privileged_port() {
        let containers = vec![DockerContainer {
            id: "pp1".to_string(),
            image: "nginx:1.25".to_string(),
            name: "web".to_string(),
            status: "running".to_string(),
            ports: vec!["80->80/tcp".to_string()],
            privileged: false,
            host_network: false,
            mounts: vec![],
            env: vec![],
        }];
        let result = DockerAuditor::audit_containers(&containers);
        assert!(result.findings.iter().any(|f| f.category == "Privileged Port"));
    }

    #[test]
    fn test_audit_no_tag_image() {
        let containers = vec![DockerContainer {
            id: "nt1".to_string(),
            image: "nginx".to_string(),
            name: "web".to_string(),
            status: "running".to_string(),
            ports: vec![],
            privileged: false,
            host_network: false,
            mounts: vec![],
            env: vec![],
        }];
        let result = DockerAuditor::audit_containers(&containers);
        assert!(result.findings.iter().any(|f| f.category == "Image Tag"));
    }

    #[test]
    fn test_audit_empty_containers() {
        let result = DockerAuditor::audit_containers(&[]);
        assert_eq!(result.total_containers, 0);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_check_dockerfile_clean() {
        let df = "FROM ubuntu:22.04\nUSER appuser\nEXPOSE 8080\nHEALTHCHECK CMD curl -f http://localhost/\n";
        let issues = DockerAuditor::check_dockerfile(df);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_check_dockerfile_user_root() {
        let df = "FROM ubuntu:22.04\nUSER root\nEXPOSE 80\nHEALTHCHECK CMD true\n";
        let issues = DockerAuditor::check_dockerfile(df);
        assert!(issues.iter().any(|i| i.contains("root")));
    }

    #[test]
    fn test_parse_docker_ps_empty() {
        let containers = DockerAuditor::parse_docker_ps("");
        assert!(containers.is_empty());
    }

    #[test]
    fn test_parse_docker_ps_multiple() {
        let output = "abc nginx:latest 1234 Up 1h 80->80/tcp web\ndef redis:7 5678 Up 2h 6379->6379 cache";
        let containers = DockerAuditor::parse_docker_ps(output);
        assert_eq!(containers.len(), 2);
    }

    #[test]
    fn test_docker_container_struct() {
        let c = DockerContainer {
            id: "test".to_string(),
            image: "nginx:1.25".to_string(),
            name: "web".to_string(),
            status: "running".to_string(),
            ports: vec!["80->80/tcp".to_string()],
            privileged: false,
            host_network: false,
            mounts: vec!["/data".to_string()],
            env: vec!["FOO=bar".to_string()],
        };
        assert_eq!(c.mounts.len(), 1);
        assert_eq!(c.env.len(), 1);
    }

    #[test]
    fn test_docker_audit_result_struct() {
        let result = DockerAuditResult {
            containers: vec![],
            findings: vec![],
            total_containers: 0,
            privileged_containers: 0,
            exposed_host_ports: vec![],
        };
        assert!(result.exposed_host_ports.is_empty());
    }
}
