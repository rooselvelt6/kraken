pub mod agent;
pub mod analyzers;
pub mod db;
pub mod patterns;
pub mod report;
pub mod scan;
pub mod tools;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    Shell,
    Other,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    StaticPatternMatching,
    LLMAgent,
    Fuzzing,
    Sanitizer,
    DependencyScan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_paths: Vec<PathBuf>,
    pub languages: Vec<Language>,
    pub enable_llm_agent: bool,
    pub enable_fuzzing: bool,
    pub enable_sanitizers: bool,
    pub enable_dependency_scan: bool,
    pub min_severity: Severity,
    pub max_findings_per_path: Option<usize>,
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
            min_severity: Severity::Medium,
            max_findings_per_path: Some(100),
        }
    }
}

pub fn new_finding_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
