use crate::{DiscoveryMethod, Finding, ScanConfig};
use std::path::Path;

pub struct VulnDB {
    connection: Option<rusqlite::Connection>,
}

impl VulnDB {
    pub fn new() -> Self {
        let conn = rusqlite::Connection::open_in_memory().ok();
        if let Some(ref c) = conn {
            let _ = c.execute(
                "CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    severity TEXT,
                    cwe TEXT,
                    description TEXT,
                    file_path TEXT,
                    line_number INTEGER
                )",
                [],
            );
        }
        Self { connection: conn }
    }

    pub fn store_finding(&self, finding: &Finding) {
        if let Some(ref conn) = self.connection {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO findings (id, severity, cwe, description, file_path, line_number) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    finding.id,
                    format!("{:?}", finding.severity),
                    finding.cwe.clone().unwrap_or_default(),
                    finding.description,
                    finding.file_path.as_ref().and_then(|p| p.to_str()).unwrap_or_default(),
                    finding.line_number.map(|l| l as i64).unwrap_or(0),
                ],
            );
        }
    }

    pub fn get_findings(&self) -> Vec<Finding> {
        let mut results = Vec::new();
        if let Some(ref conn) = self.connection {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT id, severity, cwe, description, file_path, line_number FROM findings",
            ) {
                if let Ok(mut rows) = stmt.query([]) {
                    while let Ok(Some(row)) = rows.next() {
                        let severity_str: String = row.get(1).unwrap_or_default();
                        let severity = match severity_str.as_str() {
                            "Critical" => crate::Severity::Critical,
                            "High" => crate::Severity::High,
                            "Medium" => crate::Severity::Medium,
                            "Low" => crate::Severity::Low,
                            _ => crate::Severity::Info,
                        };
                        results.push(Finding {
                            id: row.get(0).unwrap_or_default(),
                            severity,
                            cwe: row.get::<_, String>(2).ok().filter(|s| !s.is_empty()),
                            cve: None,
                            description: row.get(3).unwrap_or_default(),
                            file_path: row
                                .get::<_, String>(4)
                                .ok()
                                .filter(|s| !s.is_empty())
                                .map(std::path::PathBuf::from),
                            line_number: row.get::<_, i64>(5).ok().map(|l| l as u32),
                            vulnerable_code_snippet: None,
                            remediation: None,
                            confidence: 1.0,
                            discovery_method: DiscoveryMethod::DependencyScan,
                        });
                    }
                }
            }
        }
        results
    }

    pub fn scan_dependencies(&self, config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for target in &config.target_paths {
            if !target.exists() {
                continue;
            }

            if target.is_dir() {
                self.scan_directory_deps(target, &mut findings);
            }
        }

        findings
    }

    fn scan_directory_deps(&self, dir: &Path, findings: &mut Vec<Finding>) {
        if dir.join("Cargo.toml").exists() {
            self.scan_rust_deps(dir, findings);
        }
        if dir.join("requirements.txt").exists() {
            self.scan_python_deps(dir, findings);
        }
        if dir.join("package.json").exists() {
            self.scan_node_deps(dir, findings);
        }
        if dir.join("Gemfile").exists() {
            self.scan_ruby_deps(dir, findings);
        }
    }

    fn scan_rust_deps(&self, dir: &Path, findings: &mut Vec<Finding>) {
        let output = std::process::Command::new("cargo")
            .args(&["audit", "--json"])
            .current_dir(dir)
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                if let Ok(json_str) = String::from_utf8(output.stdout) {
                    if let Ok(audit_data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(vulns) =
                            audit_data.get("vulnerabilities").and_then(|v| v.as_array())
                        {
                            for vuln in vulns {
                                findings.push(Finding {
                                    id: crate::new_finding_id(),
                                    severity: crate::Severity::High,
                                    cwe: vuln
                                        .get("cwe")
                                        .and_then(|c| c.as_str())
                                        .map(|s| s.to_string()),
                                    cve: vuln
                                        .get("id")
                                        .and_then(|i| i.as_str())
                                        .map(|s| s.to_string()),
                                    description: vuln
                                        .get("title")
                                        .and_then(|t| t.as_str())
                                        .unwrap_or("Unknown vulnerability")
                                        .to_string(),
                                    file_path: Some(dir.join("Cargo.toml")),
                                    line_number: None,
                                    vulnerable_code_snippet: None,
                                    remediation: Some("Update dependency".to_string()),
                                    confidence: 1.0,
                                    discovery_method: DiscoveryMethod::DependencyScan,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn scan_python_deps(&self, dir: &Path, _findings: &mut Vec<Finding>) {
        let _ = std::process::Command::new("pip-audit")
            .args(&["--format", "json"])
            .current_dir(dir)
            .output();
    }

    fn scan_node_deps(&self, dir: &Path, _findings: &mut Vec<Finding>) {
        let _ = std::process::Command::new("npm")
            .args(&["audit", "--json"])
            .current_dir(dir)
            .output();
    }

    fn scan_ruby_deps(&self, dir: &Path, _findings: &mut Vec<Finding>) {
        let _ = std::process::Command::new("bundle-audit")
            .args(&["check", "--format", "json"])
            .current_dir(dir)
            .output();
    }
}

impl Default for VulnDB {
    fn default() -> Self {
        Self::new()
    }
}
