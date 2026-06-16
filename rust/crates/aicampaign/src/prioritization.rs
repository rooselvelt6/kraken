use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub cvss_score: f64,
    pub exploitability: f64,
    pub impact: String,
    pub has_exploit: bool,
    pub cve: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedVuln {
    pub vuln: VulnFinding,
    pub priority_score: f64,
    pub priority_rank: usize,
    pub recommended_action: String,
    pub urgency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizationReport {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub prioritized: Vec<PrioritizedVuln>,
}

impl PrioritizationReport {
    pub fn prioritize(vulns: &[VulnFinding]) -> PrioritizationReport {
        let mut scored: Vec<PrioritizedVuln> = vulns.iter().map(|v| {
            let score = v.cvss_score * 5.0
                + v.exploitability * 30.0
                + if v.has_exploit { 15.0 } else { 0.0 };

            let urgency = if score >= 80.0 { "CRITICAL" }
                else if score >= 60.0 { "HIGH" }
                else if score >= 40.0 { "MEDIUM" }
                else { "LOW" };

            let action = match urgency {
                "CRITICAL" => "Exploit immediately",
                "HIGH" => "Exploit within 24 hours",
                "MEDIUM" => "Schedule for next campaign",
                _ => "Monitor and re-evaluate",
            };

            PrioritizedVuln {
                vuln: v.clone(),
                priority_score: score,
                priority_rank: 0,
                recommended_action: action.to_string(),
                urgency: urgency.to_string(),
            }
        }).collect();

        scored.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap_or(std::cmp::Ordering::Equal));
        for (i, item) in scored.iter_mut().enumerate() {
            item.priority_rank = i + 1;
        }

        let critical = scored.iter().filter(|v| v.urgency == "CRITICAL").count();
        let high = scored.iter().filter(|v| v.urgency == "HIGH").count();
        let medium = scored.iter().filter(|v| v.urgency == "MEDIUM").count();

        PrioritizationReport {
            total_findings: vulns.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            prioritized: scored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vulns() -> Vec<VulnFinding> {
        vec![
            VulnFinding { id: "V-001".to_string(), name: "RCE in Apache".to_string(), severity: "CRITICAL".to_string(), cvss_score: 9.8, exploitability: 0.9, impact: "Remote Code Execution".to_string(), has_exploit: true, cve: Some("CVE-2024-0001".to_string()) },
            VulnFinding { id: "V-002".to_string(), name: "SQL Injection".to_string(), severity: "HIGH".to_string(), cvss_score: 8.6, exploitability: 0.7, impact: "Data Exfiltration".to_string(), has_exploit: true, cve: Some("CVE-2024-0002".to_string()) },
            VulnFinding { id: "V-003".to_string(), name: "XSS in login".to_string(), severity: "MEDIUM".to_string(), cvss_score: 6.1, exploitability: 0.4, impact: "Session Theft".to_string(), has_exploit: false, cve: None },
        ]
    }

    #[test]
    fn test_prioritize() {
        let vulns = sample_vulns();
        let report = PrioritizationReport::prioritize(&vulns);
        assert_eq!(report.total_findings, 3);
        assert!(report.critical_count >= 1);
    }

    #[test]
    fn test_priority_ordering() {
        let vulns = sample_vulns();
        let report = PrioritizationReport::prioritize(&vulns);
        assert!(report.prioritized[0].priority_score >= report.prioritized[1].priority_score);
    }

    #[test]
    fn test_prioritize_empty() {
        let report = PrioritizationReport::prioritize(&[]);
        assert_eq!(report.total_findings, 0);
    }

    #[test]
    fn test_prioritization_serde() {
        let report = PrioritizationReport::prioritize(&sample_vulns());
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("priority_rank"));
    }
}
