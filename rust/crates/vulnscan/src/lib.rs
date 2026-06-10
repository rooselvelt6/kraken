pub mod agent;
pub mod analyzers;
pub mod chaining;
pub mod crypto;
pub mod db;
pub mod disclosure;
pub mod exploit;
pub mod fuzz;
pub mod hypothesis;
pub mod lateral;
pub mod logic;
pub mod memory;
pub mod mitigation;
pub mod patterns;
pub mod pipeline;
pub mod recon;
pub mod report;
pub mod resume;
pub mod reverse;
pub mod sandbox;
pub mod scan;
pub mod secrets;
pub mod supply_chain;
pub mod tools;
pub mod webapp;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn value(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Rust,
    C,
    Cpp,
    JavaScript,
    TypeScript,
    Python,
    Ruby,
    Go,
    Java,
    Swift,
    Shell,
    Other,
}

impl Language {
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["rs"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cpp", "cc", "cxx", "hpp", "hh", "hxx"],
            Language::JavaScript => &["js", "mjs", "cjs"],
            Language::TypeScript => &["ts", "tsx", "mts", "cts"],
            Language::Python => &["py", "pyw"],
            Language::Ruby => &["rb"],
            Language::Go => &["go"],
            Language::Java => &["java"],
            Language::Swift => &["swift"],
            Language::Shell => &["sh", "bash", "zsh"],
            Language::Other => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DiscoveryMethod {
    #[default]
    StaticPatternMatching,
    LLMAgent,
    Fuzzing,
    Sanitizer,
    DependencyScan,
    LogicAnalysis,
    CryptoAnalysis,
    ReverseEngineering,
    SupplyChain,
    SecretsDetection,
    WebAppScan,
    ExploitChaining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitType {
    RopChain,
    HeapSpray,
    PrivilegeEscalation,
    RemoteCodeExecution,
    DenialOfService,
    InformationDisclosure,
    AuthenticationBypass,
    SandboxEscape,
    Chain,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FindingStatus {
    #[default]
    Open,
    Confirmed,
    InTriage,
    Reported,
    Accepted,
    Patched,
    Fixed,
    FalsePositive,
    WonTFix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub cve: Option<String>,
    pub description: String,
    pub file_path: Option<PathBuf>,
    pub line_number: Option<u32>,
    pub vulnerable_code_snippet: Option<String>,
    pub remediation: Option<String>,
    pub confidence: f32,
    pub discovery_method: DiscoveryMethod,
    pub exploit_code: Option<String>,
    pub exploit_type: Option<ExploitType>,
    pub chained_findings: Vec<String>,
    pub poc_validated: bool,
    pub status: FindingStatus,
    pub cvss_score: Option<f32>,
    pub severity_confidence: f32,
    pub discovered_at: DateTime<Utc>,
    pub disclosed: bool,
    pub disclosure_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_paths: Vec<PathBuf>,
    pub languages: Vec<Language>,
    pub enable_llm_agent: bool,
    pub enable_fuzzing: bool,
    pub enable_sanitizers: bool,
    pub enable_dependency_scan: bool,
    pub enable_logic_analysis: bool,
    pub enable_crypto_analysis: bool,
    pub enable_exploit_generation: bool,
    pub enable_chaining: bool,
    pub enable_secrets_detection: bool,
    pub enable_webapp_scan: bool,
    pub enable_supply_chain: bool,
    pub enable_reverse_engineering: bool,
    pub enable_container_scan: bool,
    pub enable_mitigation_check: bool,
    pub min_severity: Severity,
    pub max_findings_per_path: Option<usize>,
    pub model: String,
    pub overnight_mode: bool,
    pub container_image: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_paths: vec![],
            languages: vec![
                Language::Rust,
                Language::C,
                Language::Cpp,
                Language::JavaScript,
                Language::TypeScript,
                Language::Python,
                Language::Ruby,
            ],
            enable_llm_agent: true,
            enable_fuzzing: false,
            enable_sanitizers: false,
            enable_dependency_scan: true,
            enable_logic_analysis: false,
            enable_crypto_analysis: false,
            enable_exploit_generation: false,
            enable_chaining: false,
            enable_secrets_detection: true,
            enable_webapp_scan: false,
            enable_supply_chain: false,
            enable_reverse_engineering: false,
            enable_container_scan: false,
            enable_mitigation_check: false,
            min_severity: Severity::Medium,
            max_findings_per_path: Some(100),
            model: "deepseek/deepseek-chat".to_string(),
            overnight_mode: false,
            container_image: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub exploit_count: usize,
    pub chained_exploits: usize,
    pub duration_ms: u64,
}

impl ScanResult {
    pub fn new(findings: Vec<Finding>, files_scanned: usize, duration_ms: u64) -> Self {
        let total = findings.len();
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        let info = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();
        let exploits = findings.iter().filter(|f| f.exploit_code.is_some()).count();
        let chained = findings
            .iter()
            .filter(|f| !f.chained_findings.is_empty())
            .count();

        ScanResult {
            findings,
            files_scanned,
            total_findings: total,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            exploit_count: exploits,
            chained_exploits: chained,
            duration_ms,
        }
    }
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            id: new_finding_id(),
            severity: Severity::default(),
            cwe: None,
            cve: None,
            description: String::new(),
            file_path: None,
            line_number: None,
            vulnerable_code_snippet: None,
            remediation: None,
            confidence: 0.0,
            discovery_method: DiscoveryMethod::default(),
            exploit_code: None,
            exploit_type: None,
            chained_findings: vec![],
            poc_validated: false,
            status: FindingStatus::default(),
            cvss_score: None,
            severity_confidence: 0.0,
            discovered_at: chrono::Utc::now(),
            disclosed: false,
            disclosure_hash: None,
        }
    }
}

impl Finding {
    pub fn new(
        severity: Severity,
        description: impl Into<String>,
        file_path: Option<std::path::PathBuf>,
        line_number: Option<u32>,
        vulnerable_code_snippet: Option<String>,
        remediation: Option<String>,
        cwe: Option<String>,
        confidence: f32,
        discovery_method: DiscoveryMethod,
    ) -> Self {
        Self {
            id: new_finding_id(),
            severity,
            cwe,
            cve: None,
            description: description.into(),
            file_path,
            line_number,
            vulnerable_code_snippet,
            remediation,
            confidence,
            discovery_method,
            exploit_code: None,
            exploit_type: None,
            chained_findings: vec![],
            poc_validated: false,
            status: FindingStatus::Open,
            cvss_score: None,
            severity_confidence: confidence,
            discovered_at: chrono::Utc::now(),
            disclosed: false,
            disclosure_hash: None,
        }
    }

    pub fn info(
        description: impl Into<String>,
        file_path: Option<std::path::PathBuf>,
        line_number: Option<u32>,
        discovery_method: DiscoveryMethod,
    ) -> Self {
        Self::new(
            Severity::Info,
            description,
            file_path,
            line_number,
            None,
            None,
            None,
            0.5,
            discovery_method,
        )
    }

    pub fn with_exploit(mut self, exploit_code: String, exploit_type: ExploitType) -> Self {
        self.exploit_code = Some(exploit_code);
        self.exploit_type = Some(exploit_type);
        self.status = FindingStatus::Confirmed;
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }

    pub fn chain_to(mut self, other_id: &str) -> Self {
        self.chained_findings.push(other_id.to_string());
        self.discovery_method = DiscoveryMethod::ExploitChaining;
        self
    }

    pub fn disclose(mut self, commitment: String) -> Self {
        self.disclosed = true;
        self.disclosure_hash = Some(commitment);
        self.status = FindingStatus::Reported;
        self
    }
}

pub fn new_finding_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub use agent::{SecurityAgent, KRAKEN_SYSTEM_PROMPT};
pub use chaining::VulnerabilityChainer;
pub use crypto::CryptoAnalyzer;
pub use db::VulnDB;
pub use disclosure::DisclosurePipeline;
pub use exploit::ExploitGenerator;
pub use fuzz::FuzzGuide;
pub use hypothesis::{GeneratedHypothesis, HypothesisGenerator};
pub use lateral::{AttackGraph, AttackPath, LateralMovement};
pub use logic::LogicAnalyzer;
pub use memory::HuntMemory;
pub use mitigation::MitigationChecker;
pub use pipeline::{HuntMode, HuntPipeline, HuntReport};
pub use recon::{AttackSurface, Endpoint, EntryPoint, SurfaceRecon, Technology};
pub use report::{
    generate_cli_report, generate_html_report, generate_json_report, print_summary,
    save_html_report,
};
pub use resume::{Checkpointer, ScanCheckpoint, ScanState};
pub use scan::VulnerabilityScanner;
pub use secrets::SecretsDetector;
pub use supply_chain::SupplyChainAnalyzer;
pub use webapp::WebAppScanner;
