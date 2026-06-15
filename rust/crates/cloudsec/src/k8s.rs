

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct K8sPod {
    pub name: String,
    pub namespace: String,
    pub service_account: String,
    pub privileged: bool,
    pub host_network: bool,
    pub host_pid: bool,
    pub run_as_root: bool,
    pub capabilities: Vec<String>,
    pub volumes: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct K8sFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub resource: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct K8sAuditResult {
    pub pods: Vec<K8sPod>,
    pub findings: Vec<K8sFinding>,
    pub total_pods: usize,
    pub privileged_pods: usize,
    pub host_network_pods: usize,
    pub root_pods: usize,
}

pub struct K8sAuditor;

impl K8sAuditor {
    pub fn new() -> Self {
        K8sAuditor
    }

    pub fn audit_pod_spec(pod_spec: &str) -> Vec<K8sFinding> {
        let mut findings = Vec::new();
        let lower = pod_spec.to_lowercase();

        if lower.contains("privileged: true") || lower.contains("privileged:true") {
            findings.push(K8sFinding {
                severity: "CRITICAL".to_string(),
                category: "Privileged Container".to_string(),
                description: "Container runs in privileged mode".to_string(),
                resource: "pod".to_string(),
                recommendation: "Remove privileged: true from securityContext".to_string(),
            });
        }
        if lower.contains("hostnetwork: true") || lower.contains("hostnetwork:true") {
            findings.push(K8sFinding {
                severity: "HIGH".to_string(),
                category: "Host Network".to_string(),
                description: "Pod uses host network namespace".to_string(),
                resource: "pod".to_string(),
                recommendation: "Avoid hostNetwork, use services instead".to_string(),
            });
        }
        if lower.contains("hostpid: true") || lower.contains("hostpid:true") {
            findings.push(K8sFinding {
                severity: "HIGH".to_string(),
                category: "Host PID".to_string(),
                description: "Pod uses host PID namespace".to_string(),
                resource: "pod".to_string(),
                recommendation: "Avoid hostPID, use sidecar containers instead".to_string(),
            });
        }
        if lower.contains("runasroot: true") || lower.contains("runAsRoot: true") || lower.contains("\"runAsUser\": 0") {
            findings.push(K8sFinding {
                severity: "HIGH".to_string(),
                category: "Root User".to_string(),
                description: "Container runs as root user".to_string(),
                resource: "pod".to_string(),
                recommendation: "Set runAsNonRoot: true and runAsUser to non-zero ID".to_string(),
            });
        }
        if lower.contains("cap_add:") || lower.contains("capadd:") {
            if !lower.contains("cap_drop:") && !lower.contains("capdrop:") {
                findings.push(K8sFinding {
                    severity: "MEDIUM".to_string(),
                    category: "Linux Capabilities".to_string(),
                    description: "Container adds capabilities without dropping all first".to_string(),
                    resource: "pod".to_string(),
                    recommendation: "Drop all capabilities, then add only needed ones".to_string(),
                });
            }
        }
        if lower.contains("imagepullpolicy: never") || lower.contains("imagePullPolicy: Never") {
            findings.push(K8sFinding {
                severity: "LOW".to_string(),
                category: "Image Pull Policy".to_string(),
                description: "Image pull policy set to Never, pods may use stale images".to_string(),
                resource: "pod".to_string(),
                recommendation: "Use IfNotPresent or Always pull policy".to_string(),
            });
        }

        findings
    }

    pub fn audit_pods(pods: &[K8sPod]) -> K8sAuditResult {
        let total_pods = pods.len();
        let privileged_pods = pods.iter().filter(|p| p.privileged).count();
        let host_network_pods = pods.iter().filter(|p| p.host_network).count();
        let root_pods = pods.iter().filter(|p| p.run_as_root).count();
        let mut findings = Vec::new();

        for pod in pods {
            if pod.privileged {
                findings.push(K8sFinding {
                    severity: "CRITICAL".to_string(),
                    category: "Privileged Pod".to_string(),
                    description: format!("Pod {}/{} runs in privileged mode", pod.namespace, pod.name),
                    resource: format!("{}/{}", pod.namespace, pod.name),
                    recommendation: "Remove privileged security context".to_string(),
                });
            }
            if pod.host_network {
                findings.push(K8sFinding {
                    severity: "HIGH".to_string(),
                    category: "Host Network".to_string(),
                    description: format!("Pod {}/{} uses host network", pod.namespace, pod.name),
                    resource: format!("{}/{}", pod.namespace, pod.name),
                    recommendation: "Use Kubernetes services instead".to_string(),
                });
            }
            if pod.run_as_root {
                findings.push(K8sFinding {
                    severity: "HIGH".to_string(),
                    category: "Root Container".to_string(),
                    description: format!("Pod {}/{} runs as root", pod.namespace, pod.name),
                    resource: format!("{}/{}", pod.namespace, pod.name),
                    recommendation: "Set runAsNonRoot: true".to_string(),
                });
            }
        }

        K8sAuditResult {
            pods: pods.to_vec(),
            findings,
            total_pods,
            privileged_pods,
            host_network_pods,
            root_pods,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_privileged() {
        let spec = "privileged: true";
        let findings = K8sAuditor::audit_pod_spec(spec);
        assert!(findings.iter().any(|f| f.severity == "CRITICAL"));
    }

    #[test]
    fn test_audit_host_network() {
        let spec = "hostNetwork: true";
        let findings = K8sAuditor::audit_pod_spec(spec);
        assert!(findings.iter().any(|f| f.category == "Host Network"));
    }

    #[test]
    fn test_audit_safe_spec() {
        let spec = "runAsNonRoot: true\nrunAsUser: 1000";
        let findings = K8sAuditor::audit_pod_spec(spec);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_pods() {
        let pods = vec![K8sPod {
            name: "bad-pod".to_string(),
            namespace: "default".to_string(),
            service_account: "default".to_string(),
            privileged: true,
            host_network: false,
            host_pid: false,
            run_as_root: true,
            capabilities: vec!["NET_ADMIN".to_string()],
            volumes: vec![],
        }];
        let result = K8sAuditor::audit_pods(&pods);
        assert_eq!(result.privileged_pods, 1);
        assert_eq!(result.root_pods, 1);
    }

    #[test]
    fn test_k8s_pod() {
        let p = K8sPod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            service_account: "sa".to_string(),
            privileged: false,
            host_network: false,
            host_pid: false,
            run_as_root: false,
            capabilities: vec![],
            volumes: vec![],
        };
        let json = serde_json::to_string_pretty(&p).unwrap();
        assert!(json.contains("\"privileged\": false"));
    }
}
