use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use std::path::Path;

pub struct KubernetesAnalyzer;

impl Default for KubernetesAnalyzer {
    fn default() -> Self {
        Self
    }
}

impl super::LanguageAnalyzer for KubernetesAnalyzer {
    fn language(&self) -> Language {
        Language::Kubernetes
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["yaml", "yml"]
    }

    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        let lines: Vec<&str> = content.lines().collect();

        let mut in_container = false;
        let mut container_indent = 0;
        let mut in_security_context = false;
        let mut security_context_indent = 0;
        let mut has_privileged = false;
        let mut has_allow_escalation = false;
        let mut has_read_only_rootfs = false;
        let mut has_run_as_non_root = false;
        let mut has_container_resources = false;
        let mut has_seccomp = false;

        let indent_of = |line: &str| -> usize {
            line.chars().take_while(|c| c.is_whitespace()).count()
        };

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let lineno = i as u32 + 1;

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let ind = indent_of(line);

            if let Some(rest) = trimmed.strip_prefix("kind:") {
                let kind = rest.trim().to_lowercase();
                if kind == "clusterrole" || kind == "clusterrolebinding" {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-732",
                        "ClusterRole/Binding with cluster-wide scope",
                        "ClusterRole grants permissions across all namespaces. Prefer Role/RoleBinding scoped to specific namespaces unless absolutely necessary.",
                        0.85,
                    ));
                }
            }

            if trimmed.ends_with("- name: ") || trimmed.starts_with("- name: ") || trimmed == "containers:" || trimmed.starts_with("containers:") {
                in_container = true;
                container_indent = ind;
                has_privileged = false;
                has_allow_escalation = false;
                has_read_only_rootfs = false;
                has_run_as_non_root = false;
                has_container_resources = false;
                has_seccomp = false;
                continue;
            }

            if in_container && ind <= container_indent && !trimmed.starts_with("-") && !trimmed.starts_with("securityContext") && !trimmed.starts_with("resources") && !trimmed.starts_with("image:") && !trimmed.starts_with("name:") && !trimmed.starts_with("ports:") && !trimmed.starts_with("env:") && !trimmed.starts_with("volumeMounts:") && !trimmed.starts_with("command:") && !trimmed.starts_with("args:") && !trimmed.starts_with("stdin:") && !trimmed.starts_with("tty:") && !trimmed.starts_with("workingDir:") {
                flush_container(&mut findings, file_path, lineno, &mut has_privileged, &mut has_allow_escalation, &mut has_read_only_rootfs, &mut has_run_as_non_root, &mut has_container_resources, &mut has_seccomp);
                in_container = false;
            }

            if in_container && trimmed.starts_with("securityContext:") {
                in_security_context = true;
                security_context_indent = ind;
                continue;
            }

            if in_security_context && ind <= security_context_indent && !trimmed.starts_with("-") {
                in_security_context = false;
            }

            if in_security_context {
                if let Some(rest) = trimmed.strip_prefix("privileged:") {
                    let val = rest.trim();
                    has_privileged = val.eq_ignore_ascii_case("true");
                }
                if let Some(rest) = trimmed.strip_prefix("allowPrivilegeEscalation:") {
                    let val = rest.trim();
                    has_allow_escalation = val.eq_ignore_ascii_case("true");
                }
                if let Some(rest) = trimmed.strip_prefix("readOnlyRootFilesystem:") {
                    let val = rest.trim();
                    has_read_only_rootfs = val.eq_ignore_ascii_case("true");
                }
                if let Some(rest) = trimmed.strip_prefix("runAsNonRoot:") {
                    let val = rest.trim();
                    has_run_as_non_root = val.eq_ignore_ascii_case("true");
                }
                if trimmed.starts_with("seccompProfile:") || trimmed.starts_with("seLinuxOptions:") {
                    has_seccomp = true;
                }
            }

            if in_container && trimmed.starts_with("resources:") {
                has_container_resources = true;
            }

            if in_container && trimmed.starts_with("imagePullPolicy:") {
                let val = trimmed["imagePullPolicy:".len()..].trim();
                if val == "Always" {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Info,
                        "CWE-1104",
                        "imagePullPolicy: Always",
                        "imagePullPolicy: Always forces re-pull on every pod start, increasing startup time and network dependency. Use 'IfNotPresent' for local clusters.",
                        0.4,
                    ));
                }
            }

            if let Some(rest) = trimmed.strip_prefix("hostNetwork:") {
                let val = rest.trim();
                if val.eq_ignore_ascii_case("true") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Critical,
                        "CWE-200",
                        "hostNetwork: true exposes host network",
                        "Setting hostNetwork: true gives the container access to the host's network stack. Remove or set to false unless explicitly required for networking plugins.",
                        0.95,
                    ));
                }
            }

            if let Some(rest) = trimmed.strip_prefix("hostPID:") {
                let val = rest.trim();
                if val.eq_ignore_ascii_case("true") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-200",
                        "hostPID: true exposes host process table",
                        "Setting hostPID: true allows the container to see all host processes. Remove or set to false unless absolutely needed.",
                        0.9,
                    ));
                }
            }

            if let Some(rest) = trimmed.strip_prefix("privileged:") {
                let val = rest.trim();
                if val.eq_ignore_ascii_case("true") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Critical,
                        "CWE-250",
                        "Privileged container",
                        "privileged: true disables all security features. Remove privileged mode and use specific capabilities (capabilities:) instead.",
                        0.95,
                    ));
                }
            }

            let lower = trimmed.to_lowercase();
            if (lower.contains("password") || lower.contains("secret") || lower.contains("token") || lower.contains("api_key"))
                && !lower.starts_with("#") && (lower.contains(": ") || lower.contains(":  ")) {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-798",
                        "Possible hardcoded secret in manifest",
                        "Avoid hardcoding secrets in Kubernetes manifests. Use Secrets resources with external secret stores (SealedSecrets, External Secrets Operator, Vault).",
                        0.85,
                    ));
                }
        }

        if in_container {
            flush_container(&mut findings, file_path, lines.len() as u32, &mut has_privileged, &mut has_allow_escalation, &mut has_read_only_rootfs, &mut has_run_as_non_root, &mut has_container_resources, &mut has_seccomp);
        }

        findings
    }
}

#[allow(clippy::too_many_arguments)]
fn flush_container(
    findings: &mut Vec<Finding>,
    file_path: &Path,
    lineno: u32,
    has_privileged: &mut bool,
    has_allow_escalation: &mut bool,
    has_read_only_rootfs: &mut bool,
    has_run_as_non_root: &mut bool,
    has_container_resources: &mut bool,
    has_seccomp: &mut bool,
) {
    if *has_allow_escalation {
        findings.push(make_finding(
            file_path, lineno, "allowPrivilegeEscalation: true",
            Severity::High,
            "CWE-250",
            "allowPrivilegeEscalation enabled",
            "Set allowPrivilegeEscalation: false in securityContext to prevent privilege escalation via setuid binaries.",
            0.9,
        ));
    }
    if *has_privileged {
        findings.push(make_finding(
            file_path, lineno, "privileged: true",
            Severity::Critical,
            "CWE-250",
            "Privileged container",
            "privileged: true disables all security features. Remove privileged mode and use specific capabilities instead.",
            0.95,
        ));
    }
    if !*has_run_as_non_root {
        findings.push(make_finding(
            file_path, lineno, "securityContext.runAsNonRoot not set",
            Severity::Medium,
            "CWE-250",
            "Container may run as root",
            "Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID to prevent root execution.",
            0.8,
        ));
    }
    if !*has_read_only_rootfs {
        findings.push(make_finding(
            file_path, lineno, "readOnlyRootFilesystem not set",
            Severity::Low,
            "CWE-22",
            "Container has writable root filesystem",
            "Set securityContext.readOnlyRootFilesystem: true to prevent writes to the container filesystem. Use emptyDir volumes for temporary writes.",
            0.7,
        ));
    }
    if !*has_container_resources {
        findings.push(make_finding(
            file_path, lineno, "resources not set",
            Severity::Medium,
            "CWE-770",
            "Container without resource limits",
            "Set resources.requests and resources.limits for CPU and memory to prevent resource exhaustion and DoS.",
            0.8,
        ));
    }
    if !*has_seccomp {
        findings.push(make_finding(
            file_path, lineno, "seccomp profile not set",
            Severity::Low,
            "CWE-693",
            "No seccomp profile configured",
            "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost to restrict syscalls.",
            0.65,
        ));
    }
    *has_privileged = false;
    *has_allow_escalation = false;
    *has_read_only_rootfs = false;
    *has_run_as_non_root = false;
    *has_container_resources = false;
    *has_seccomp = false;
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    file_path: &Path,
    line_number: u32,
    snippet: &str,
    severity: Severity,
    cwe: &str,
    title: &str,
    remediation: &str,
    confidence: f32,
) -> Finding {
    Finding {
        id: crate::new_finding_id(),
        severity,
        cwe: Some(cwe.to_string()),
        cve: None,
        description: format!("{} — {}", title, cwe),
        file_path: Some(file_path.to_path_buf()),
        line_number: Some(line_number),
        vulnerable_code_snippet: Some(snippet.trim().to_string()),
        remediation: Some(remediation.to_string()),
        confidence,
        discovery_method: DiscoveryMethod::StaticPatternMatching,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::LanguageAnalyzer;
    use std::path::PathBuf;

    fn analyze(content: &str) -> Vec<Finding> {
        let analyzer = KubernetesAnalyzer;
        analyzer.analyze(content, &PathBuf::from("deployment.yaml"), &ScanConfig::default())
    }

    #[test]
    fn test_privileged_container() {
        let findings = analyze(r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
"#);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-250")));
    }

    #[test]
    fn test_host_network() {
        let findings = analyze(r#"
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: test
    image: nginx
"#);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200") && f.description.contains("hostNetwork")));
    }

    #[test]
    fn test_host_pid() {
        let findings = analyze(r#"
apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
  - name: test
    image: nginx
"#);
        assert!(findings.iter().any(|f| f.description.contains("hostPID")));
    }

    #[test]
    fn test_cluster_role() {
        let findings = analyze(r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-cluster-role
"#);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-732")));
    }

    #[test]
    fn test_no_security_context_warns() {
        let findings = analyze(r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx
"#);
        assert!(findings.iter().any(|f| f.vulnerable_code_snippet.as_deref().unwrap_or("").contains("runAsNonRoot")));
        assert!(findings.iter().any(|f| f.vulnerable_code_snippet.as_deref().unwrap_or("").contains("resources not set")));
    }

    #[test]
    fn test_hardcoded_secret() {
        let findings = analyze(r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: test
    image: nginx
    env:
    - name: DB_PASSWORD
      value: "supersecret"
"#);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-798")));
    }

    #[test]
    fn test_secure_pod_minimal_findings() {
        let manifest = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
"#;
        let findings = analyze(manifest);
        let high_or_critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High || f.severity == Severity::Critical).collect();
        assert!(high_or_critical.is_empty(), "Secure pod should not have High/Critical findings, got: {:?}", high_or_critical);
    }
}
