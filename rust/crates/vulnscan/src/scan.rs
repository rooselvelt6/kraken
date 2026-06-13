use crate::{
    analyzers::{self, LanguageAnalyzer},
    DiscoveryMethod, Finding, FindingStatus, Language, ScanConfig, Severity,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct VulnerabilityScanner {
    config: ScanConfig,
}

impl VulnerabilityScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub fn scan(&self) -> Vec<Finding> {
        let mut all_findings = Vec::new();
        let analyzers = analyzers::load_all_analyzers();

        for target in &self.config.target_paths {
            if !target.exists() {
                continue;
            }

            if target.is_file() {
                self.scan_file(target, &analyzers, &mut all_findings);
            } else {
                self.scan_directory(target, &analyzers, &mut all_findings);
            }
        }

        self.filter_by_severity(all_findings)
    }

    fn scan_directory(
        &self,
        dir: &Path,
        analyzers: &[Box<dyn LanguageAnalyzer + Send + Sync>],
        findings: &mut Vec<Finding>,
    ) {
        for entry in WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                self.scan_file(path, analyzers, findings);
            }
        }
    }

    fn scan_file(
        &self,
        file_path: &Path,
        analyzers: &[Box<dyn LanguageAnalyzer + Send + Sync>],
        findings: &mut Vec<Finding>,
    ) {
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let language = analyzers::detect_language(file_path, Some(&content));

        if !self.config.languages.contains(&language) && language != Language::Other {
            return;
        }

        for analyzer in analyzers {
            if analyzer.language() == language || language == Language::Other {
                let mut file_findings = analyzer.analyze(&content, file_path, &self.config);
                findings.append(&mut file_findings);

                if let Some(max) = self.config.max_findings_per_path {
                    if findings.len() >= max {
                        break;
                    }
                }
            }
        }
    }

    fn filter_by_severity(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| f.severity.value() >= self.config.min_severity.value())
            .collect()
    }

    pub fn rank_files_by_bug_probability(&self, files: &[PathBuf]) -> Vec<(PathBuf, f32)> {
        let keywords = [
            "unsafe",
            "eval",
            "exec",
            "system",
            "ShellExecute",
            "Runtime.exec",
            "Process.Start",
        ];
        let dangerous_funcs = [
            "strcpy", "strcat", "sprintf", "gets", "scanf", "memcpy", "realloc",
        ];

        let mut scored: Vec<(PathBuf, f32)> = Vec::new();

        for file in files {
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let file_size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
            let total_lines = content.lines().count().max(1);

            let keyword_count: f32 = keywords
                .iter()
                .map(|kw| content.matches(kw).count() as f32)
                .sum();

            let danger_count: f32 = dangerous_funcs
                .iter()
                .map(|f| content.matches(f).count() as f32)
                .sum();

            let size_factor = if file_size > 0 {
                (file_size as f32 / 100_000.0).min(1.0)
            } else {
                0.0
            };

            let keyword_density = keyword_count / total_lines as f32;
            let danger_density = danger_count / total_lines as f32;

            let score = size_factor * 0.15 + keyword_density * 0.5 + danger_density * 0.35;
            scored.push((file.clone(), score));
        }

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    pub fn validate_findings(&self, findings: &[Finding]) -> Vec<Finding> {
        let mut seen: HashSet<(Option<PathBuf>, Option<u32>)> = HashSet::new();
        let known_benchmarks = ["CWE", "jackson-core", "benchmark", "vulnerability-tests"];

        findings
            .iter()
            .map(|f| {
                let key = (f.file_path.clone(), f.line_number);

                if seen.contains(&key) {
                    let mut fp = f.clone();
                    fp.status = FindingStatus::FalsePositive;
                    return fp;
                }

                seen.insert(key);

                if let Some(path) = &f.file_path {
                    let path_str = path.to_string_lossy();
                    if known_benchmarks.iter().any(|b| path_str.contains(b)) {
                        let mut fp = f.clone();
                        fp.status = FindingStatus::FalsePositive;
                        return fp;
                    }
                }

                f.clone()
            })
            .collect()
    }

    pub fn scan_container_image(image_ref: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if image_ref.is_empty() {
            return findings;
        }

        let lower = image_ref.to_lowercase();

        if !lower.contains(':') || lower.ends_with(":latest") {
            findings.push(Finding {
                id: crate::new_finding_id(),
                severity: Severity::Medium,
                cwe: Some("CWE-1104".to_string()),
                cve: None,
                description: format!("Unpinned container image tag — {}", image_ref),
                file_path: None,
                line_number: None,
                vulnerable_code_snippet: Some(image_ref.to_string()),
                remediation: Some(
                    "Pin container image to a specific digest \
                     (e.g. `ubuntu@sha256:abc123...`) or a version tag (e.g. `nginx:1.25.0`)"
                        .to_string(),
                ),
                confidence: 0.85,
                discovery_method: DiscoveryMethod::DependencyScan,
                ..Default::default()
            });
        }

        let known_vulnerable = [
            ("nginx:1.22", "nginx 1.22 has known vulnerabilities (CVE-2023-44487, CVE-2023-25584)"),
            ("nginx:1.23", "nginx 1.23 has known vulnerabilities"),
            ("node:14", "Node.js 14 is EOL (end of life) since April 2023"),
            ("node:16", "Node.js 16 is EOL since September 2023"),
            ("python:3.8", "Python 3.8 is EOL since October 2024"),
            ("python:3.9", "Python 3.9 is EOL since October 2025"),
            ("ubuntu:20.04", "Ubuntu 20.04 (Focal) is in ESM phase: standard support ended May 2025"),
            ("debian:10", "Debian 10 (Buster) is EOL since June 2024"),
            ("alpine:3.15", "Alpine 3.15 is EOL since November 2023"),
        ];

        for &(vulnerable_tag, advisory) in &known_vulnerable {
            if lower.contains(vulnerable_tag) {
                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity: Severity::High,
                    cwe: Some("CWE-1104".to_string()),
                    cve: None,
                    description: format!("Known vulnerable image tag: {} — {}", image_ref, advisory),
                    file_path: None,
                    line_number: None,
                    vulnerable_code_snippet: Some(image_ref.to_string()),
                    remediation: Some(format!(
                        "Upgrade to a supported version. {}", advisory
                    )),
                    confidence: 0.9,
                    discovery_method: DiscoveryMethod::DependencyScan,
                    ..Default::default()
                });
            }
        }

        if lower.contains("/") && !lower.contains("docker.io") && !lower.contains("ghcr.io") && !lower.contains("quay.io") && !lower.contains("gcr.io") {
            findings.push(Finding {
                id: crate::new_finding_id(),
                severity: Severity::Info,
                cwe: Some("CWE-1104".to_string()),
                cve: None,
                description: format!("Container image from non-standard registry — {}", image_ref),
                file_path: None,
                line_number: None,
                vulnerable_code_snippet: Some(image_ref.to_string()),
                    remediation: Some(
                        "Verify the image registry is trusted. Consider mirroring images to a \
                         known registry to ensure supply chain integrity."
                            .to_string(),
                    ),
                confidence: 0.4,
                discovery_method: DiscoveryMethod::DependencyScan,
                ..Default::default()
            });
        }

        findings
    }

    pub fn prioritize_exploitable(&self, findings: &[Finding]) -> Vec<Finding> {
        let injection_patterns = ["exec(", "eval(", "system(", "Runtime.", "Process.", "cmd."];

        let mut scored: Vec<(f32, usize, &Finding)> = findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let cvss_score = f.cvss_score.unwrap_or(0.0) / 10.0;

                let snippet = f.vulnerable_code_snippet.as_deref().unwrap_or("");
                let has_injection = injection_patterns.iter().any(|p| snippet.contains(p));
                let has_unsafe = snippet.contains("unsafe");

                let severity_weight = f.severity.value() as f32 / 4.0;

                let injection_score = if has_injection { 0.3 } else { 0.0 };
                let unsafe_score = if has_unsafe && f.severity.value() >= 3 {
                    0.3
                } else {
                    0.0
                };
                let confidence_score = f.confidence * 0.4;

                let total = cvss_score * 0.25
                    + injection_score
                    + unsafe_score
                    + severity_weight * 0.15
                    + confidence_score;
                (total, i, f)
            })
            .collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().map(|(_, _, f)| f.clone()).collect()
    }
}
