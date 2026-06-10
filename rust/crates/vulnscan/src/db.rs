use crate::{DiscoveryMethod, ExploitType, Finding, FindingStatus, ScanConfig, Severity};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn db_path() -> Option<PathBuf> {
    let base = dirs::data_dir()?
        .join(".kraken")
        .join("vulnscan")
        .join("db");
    std::fs::create_dir_all(&base).ok()?;
    Some(base.join("vulnscan.db"))
}

fn severity_from_str(s: &str) -> Severity {
    match s {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn discovery_method_from_str(s: &str) -> DiscoveryMethod {
    match s {
        "StaticPatternMatching" => DiscoveryMethod::StaticPatternMatching,
        "LLMAgent" => DiscoveryMethod::LLMAgent,
        "Fuzzing" => DiscoveryMethod::Fuzzing,
        "Sanitizer" => DiscoveryMethod::Sanitizer,
        "DependencyScan" => DiscoveryMethod::DependencyScan,
        "LogicAnalysis" => DiscoveryMethod::LogicAnalysis,
        "CryptoAnalysis" => DiscoveryMethod::CryptoAnalysis,
        "ReverseEngineering" => DiscoveryMethod::ReverseEngineering,
        "SupplyChain" => DiscoveryMethod::SupplyChain,
        "SecretsDetection" => DiscoveryMethod::SecretsDetection,
        "WebAppScan" => DiscoveryMethod::WebAppScan,
        "ExploitChaining" => DiscoveryMethod::ExploitChaining,
        _ => DiscoveryMethod::DependencyScan,
    }
}

fn exploit_type_from_str(s: &str) -> Option<ExploitType> {
    match s {
        "RopChain" => Some(ExploitType::RopChain),
        "HeapSpray" => Some(ExploitType::HeapSpray),
        "PrivilegeEscalation" => Some(ExploitType::PrivilegeEscalation),
        "RemoteCodeExecution" => Some(ExploitType::RemoteCodeExecution),
        "DenialOfService" => Some(ExploitType::DenialOfService),
        "InformationDisclosure" => Some(ExploitType::InformationDisclosure),
        "AuthenticationBypass" => Some(ExploitType::AuthenticationBypass),
        "SandboxEscape" => Some(ExploitType::SandboxEscape),
        "Chain" => Some(ExploitType::Chain),
        "Unknown" => Some(ExploitType::Unknown),
        _ => None,
    }
}

fn finding_status_from_str(s: &str) -> FindingStatus {
    match s {
        "Open" => FindingStatus::Open,
        "Confirmed" => FindingStatus::Confirmed,
        "InTriage" => FindingStatus::InTriage,
        "Reported" => FindingStatus::Reported,
        "Accepted" => FindingStatus::Accepted,
        "Patched" => FindingStatus::Patched,
        "Fixed" => FindingStatus::Fixed,
        "FalsePositive" => FindingStatus::FalsePositive,
        "WonTFix" => FindingStatus::WonTFix,
        _ => FindingStatus::Open,
    }
}

pub struct VulnDB {
    connection: Option<Connection>,
}

impl VulnDB {
    pub fn new_persistent() -> Self {
        let conn = db_path().and_then(|p| Connection::open(p).ok());
        if let Some(ref conn) = conn {
            Self::run_migrations(conn);
        }
        Self { connection: conn }
    }

    pub fn new_in_memory() -> Self {
        let conn = Connection::open_in_memory().ok();
        if let Some(ref conn) = conn {
            Self::run_migrations(conn);
        }
        Self { connection: conn }
    }

    fn run_migrations(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _migrations (
                version INTEGER PRIMARY KEY
            );",
        )
        .ok();

        let current_version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM _migrations",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if current_version < 1 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    cwe TEXT,
                    cve TEXT,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    vulnerable_code_snippet TEXT,
                    remediation TEXT,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    discovery_method TEXT NOT NULL,
                    exploit_code TEXT,
                    exploit_type TEXT,
                    chained_findings TEXT NOT NULL DEFAULT '[]',
                    poc_validated INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'Open',
                    cvss_score REAL,
                    severity_confidence REAL NOT NULL DEFAULT 0.0,
                    discovered_at TEXT NOT NULL,
                    disclosed INTEGER NOT NULL DEFAULT 0,
                    disclosure_hash TEXT
                );",
            )
            .ok();
            conn.execute("INSERT INTO _migrations (version) VALUES (1)", [])
                .ok();
        }
    }

    pub fn store_finding(&self, finding: &Finding) {
        if let Some(ref conn) = self.connection {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO findings (
                    id, severity, cwe, cve, description, file_path, line_number,
                    vulnerable_code_snippet, remediation, confidence, discovery_method,
                    exploit_code, exploit_type, chained_findings, poc_validated,
                    status, cvss_score, severity_confidence, discovered_at,
                    disclosed, disclosure_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    finding.id,
                    format!("{:?}", finding.severity),
                    finding.cwe,
                    finding.cve,
                    finding.description,
                    finding.file_path.as_ref().map(|p| p.to_string_lossy().to_string()),
                    finding.line_number.map(|l| l as i64),
                    finding.vulnerable_code_snippet,
                    finding.remediation,
                    finding.confidence,
                    format!("{:?}", finding.discovery_method),
                    finding.exploit_code,
                    finding.exploit_type.map(|e| format!("{:?}", e)),
                    serde_json::to_string(&finding.chained_findings).unwrap_or_default(),
                    finding.poc_validated as i32,
                    format!("{:?}", finding.status),
                    finding.cvss_score,
                    finding.severity_confidence,
                    finding.discovered_at.to_rfc3339(),
                    finding.disclosed as i32,
                    finding.disclosure_hash,
                ],
            );
        }
    }

    pub fn store_findings(&self, findings: &[Finding]) {
        for finding in findings {
            self.store_finding(finding);
        }
    }

    pub fn get_finding(&self, id: &str) -> Option<Finding> {
        self.connection.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT id, severity, cwe, cve, description, file_path, line_number,
                    vulnerable_code_snippet, remediation, confidence, discovery_method,
                    exploit_code, exploit_type, chained_findings, poc_validated,
                    status, cvss_score, severity_confidence, discovered_at,
                    disclosed, disclosure_hash
                FROM findings WHERE id = ?1",
                params![id],
                |row| {
                    let chained_str: String = row.get(13)?;
                    Ok(Finding {
                        id: row.get(0)?,
                        severity: severity_from_str(&row.get::<_, String>(1)?),
                        cwe: row.get(2)?,
                        cve: row.get(3)?,
                        description: row.get(4)?,
                        file_path: row.get::<_, Option<String>>(5)?.map(PathBuf::from),
                        line_number: row.get::<_, Option<i64>>(6)?.map(|l| l as u32),
                        vulnerable_code_snippet: row.get(7)?,
                        remediation: row.get(8)?,
                        confidence: row.get(9)?,
                        discovery_method: discovery_method_from_str(&row.get::<_, String>(10)?),
                        exploit_code: row.get(11)?,
                        exploit_type: row
                            .get::<_, Option<String>>(12)?
                            .and_then(|s| exploit_type_from_str(&s)),
                        chained_findings: serde_json::from_str(&chained_str).unwrap_or_default(),
                        poc_validated: row.get::<_, i32>(14)? != 0,
                        status: finding_status_from_str(&row.get::<_, String>(15)?),
                        cvss_score: row.get(16)?,
                        severity_confidence: row.get(17)?,
                        discovered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(18)?)
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        disclosed: row.get::<_, i32>(19)? != 0,
                        disclosure_hash: row.get(20)?,
                    })
                },
            )
            .ok()
        })
    }

    pub fn get_findings(&self) -> Vec<Finding> {
        self.query_findings(
            "SELECT id, severity, cwe, cve, description, file_path, line_number,
                vulnerable_code_snippet, remediation, confidence, discovery_method,
                exploit_code, exploit_type, chained_findings, poc_validated,
                status, cvss_score, severity_confidence, discovered_at,
                disclosed, disclosure_hash
            FROM findings ORDER BY discovered_at DESC",
            [],
        )
    }

    pub fn get_findings_by_severity(&self, severity: Severity) -> Vec<Finding> {
        self.query_findings(
            "SELECT id, severity, cwe, cve, description, file_path, line_number,
                vulnerable_code_snippet, remediation, confidence, discovery_method,
                exploit_code, exploit_type, chained_findings, poc_validated,
                status, cvss_score, severity_confidence, discovered_at,
                disclosed, disclosure_hash
            FROM findings WHERE severity = ?1 ORDER BY discovered_at DESC",
            params![format!("{:?}", severity)],
        )
    }

    pub fn get_findings_by_status(&self, status: FindingStatus) -> Vec<Finding> {
        self.query_findings(
            "SELECT id, severity, cwe, cve, description, file_path, line_number,
                vulnerable_code_snippet, remediation, confidence, discovery_method,
                exploit_code, exploit_type, chained_findings, poc_validated,
                status, cvss_score, severity_confidence, discovered_at,
                disclosed, disclosure_hash
            FROM findings WHERE status = ?1 ORDER BY discovered_at DESC",
            params![format!("{:?}", status)],
        )
    }

    fn query_findings(&self, sql: &str, params: impl rusqlite::Params) -> Vec<Finding> {
        let mut results = Vec::new();
        if let Some(ref conn) = self.connection {
            if let Ok(mut stmt) = conn.prepare(sql) {
                if let Ok(mut rows) = stmt.query(params) {
                    while let Ok(Some(row)) = rows.next() {
                        let chained_str: String = match row.get(13) {
                            Ok(s) => s,
                            _ => continue,
                        };
                        results.push(Finding {
                            id: row.get(0).unwrap_or_default(),
                            severity: severity_from_str(
                                &row.get::<_, String>(1).unwrap_or_default(),
                            ),
                            cwe: row.get(2).ok(),
                            cve: row.get(3).ok(),
                            description: row.get(4).unwrap_or_default(),
                            file_path: row
                                .get::<_, Option<String>>(5)
                                .ok()
                                .flatten()
                                .map(PathBuf::from),
                            line_number: row
                                .get::<_, Option<i64>>(6)
                                .ok()
                                .flatten()
                                .map(|l| l as u32),
                            vulnerable_code_snippet: row.get(7).ok(),
                            remediation: row.get(8).ok(),
                            confidence: row.get(9).unwrap_or(0.0),
                            discovery_method: discovery_method_from_str(
                                &row.get::<_, String>(10).unwrap_or_default(),
                            ),
                            exploit_code: row.get(11).ok(),
                            exploit_type: row
                                .get::<_, Option<String>>(12)
                                .ok()
                                .flatten()
                                .and_then(|s| exploit_type_from_str(&s)),
                            chained_findings: serde_json::from_str(&chained_str)
                                .unwrap_or_default(),
                            poc_validated: row.get::<_, i32>(14).unwrap_or(0) != 0,
                            status: finding_status_from_str(
                                &row.get::<_, String>(15).unwrap_or_default(),
                            ),
                            cvss_score: row.get(16).ok(),
                            severity_confidence: row.get(17).unwrap_or(0.0),
                            discovered_at: row
                                .get::<_, String>(18)
                                .ok()
                                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_else(Utc::now),
                            disclosed: row.get::<_, i32>(19).unwrap_or(0) != 0,
                            disclosure_hash: row.get(20).ok(),
                        });
                    }
                }
            }
        }
        results
    }

    pub fn update_status(&self, id: &str, status: FindingStatus) {
        if let Some(ref conn) = self.connection {
            let _ = conn.execute(
                "UPDATE findings SET status = ?1 WHERE id = ?2",
                params![format!("{:?}", status), id],
            );
        }
    }

    pub fn update_disclosure(&self, id: &str, hash: &str) {
        if let Some(ref conn) = self.connection {
            let _ = conn.execute(
                "UPDATE findings SET disclosed = 1, disclosure_hash = ?1 WHERE id = ?2",
                params![hash, id],
            );
        }
    }

    pub fn get_statistics(&self) -> Value {
        let mut stats = json!({
            "total": 0,
            "by_severity": {},
            "by_status": {},
            "avg_confidence": 0.0,
            "avg_cvss": null,
            "exploited": 0,
            "disclosed": 0,
            "chained": 0,
        });
        if let Some(ref conn) = self.connection {
            if let Ok(total) = conn.query_row("SELECT COUNT(*) FROM findings", [], |row| {
                row.get::<_, i64>(0)
            }) {
                stats["total"] = json!(total);
            }
            for s in &["Info", "Low", "Medium", "High", "Critical"] {
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM findings WHERE severity = ?1",
                    params![s],
                    |row| row.get::<_, i64>(0),
                ) {
                    stats["by_severity"][s.to_lowercase()] = json!(count);
                }
            }
            for s in &[
                "Open",
                "Confirmed",
                "InTriage",
                "Reported",
                "Accepted",
                "Patched",
                "Fixed",
                "FalsePositive",
                "WonTFix",
            ] {
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM findings WHERE status = ?1",
                    params![s],
                    |row| row.get::<_, i64>(0),
                ) {
                    stats["by_status"][s.to_string()] = json!(count);
                }
            }
            if let Ok(avg) = conn.query_row("SELECT AVG(confidence) FROM findings", [], |row| {
                row.get::<_, f64>(0)
            }) {
                stats["avg_confidence"] = json!(avg);
            }
            if let Ok(avg_cvss) = conn.query_row(
                "SELECT AVG(cvss_score) FROM findings WHERE cvss_score IS NOT NULL",
                [],
                |row| row.get::<_, f64>(0),
            ) {
                stats["avg_cvss"] = json!(avg_cvss);
            }
            if let Ok(count) = conn.query_row(
                "SELECT COUNT(*) FROM findings WHERE exploit_code IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0),
            ) {
                stats["exploited"] = json!(count);
            }
            if let Ok(count) = conn.query_row(
                "SELECT COUNT(*) FROM findings WHERE disclosed = 1",
                [],
                |row| row.get::<_, i64>(0),
            ) {
                stats["disclosed"] = json!(count);
            }
            if let Ok(count) = conn.query_row(
                "SELECT COUNT(*) FROM findings WHERE chained_findings != '[]'",
                [],
                |row| row.get::<_, i64>(0),
            ) {
                stats["chained"] = json!(count);
            }
        }
        stats
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
                                    ..Default::default()
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
        Self::new_persistent()
    }
}
