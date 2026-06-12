pub mod collector;
pub mod dns;
pub mod email;
pub mod search;
pub mod social;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintTarget {
    pub value: String,
    pub kind: TargetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetKind {
    Domain,
    Email,
    IpAddress,
    Username,
    Url,
    Organization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintFinding {
    pub source: OsintSource,
    pub kind: FindingKind,
    pub value: String,
    pub context: Option<String>,
    pub confidence: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintSource {
    pub name: String,
    pub reliability: Reliability,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reliability {
    High,
    Medium,
    Low,
    Untrusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingKind {
    Email,
    Url,
    IpAddress,
    PhoneNumber,
    Username,
    DnsRecord,
    WhoisInfo,
    Technology,
    Subdomain,
    SocialProfile,
    BreachData,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintReport {
    pub target: OsintTarget,
    pub findings: Vec<OsintFinding>,
    pub summary: String,
    pub collected_at: String,
    pub source_count: usize,
}

impl OsintReport {
    pub fn new(target: OsintTarget, findings: Vec<OsintFinding>) -> Self {
        let collected_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut sources: Vec<&str> = findings.iter().map(|f| f.source.name.as_str()).collect();
        sources.sort_unstable();
        sources.dedup();
        let source_count = sources.len();
        let summary = format!(
            "Collected {} findings from {} sources for target '{}'",
            findings.len(),
            source_count,
            target.value
        );
        Self {
            target,
            findings,
            summary,
            collected_at,
            source_count,
        }
    }
}
