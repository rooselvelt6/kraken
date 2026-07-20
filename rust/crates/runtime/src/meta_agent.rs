use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Roles a sub-agent can assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    StaticAnalysis,
    LlmSemanticAnalysis,
    ExploitGeneration,
    CrossValidator,
}

impl AgentRole {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::StaticAnalysis => "StaticAnalysis",
            Self::LlmSemanticAnalysis => "LlmSemanticAnalysis",
            Self::ExploitGeneration => "ExploitGeneration",
            Self::CrossValidator => "CrossValidator",
        }
    }

    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::StaticAnalysis => "Performs static code analysis using AST patterns and heuristics",
            Self::LlmSemanticAnalysis => "Uses LLM to understand code semantics and vulnerability context",
            Self::ExploitGeneration => "Generates exploit payloads and proof-of-concept code",
            Self::CrossValidator => "Validates findings across multiple agent outputs",
        }
    }
}

/// A single finding reported by a sub-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub agent: AgentRole,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

/// Result from a sub-agent's analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult {
    pub role: AgentRole,
    pub findings: Vec<AgentFinding>,
    pub analysis_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

/// Cross-validated finding from multiple agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedFinding {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: f64,
    pub supporting_agents: Vec<AgentRole>,
    pub evidence: Vec<String>,
    pub validation_score: f64,
}

/// The meta-agent that coordinates sub-agents.
pub struct MetaAgent {
    sub_agents: Vec<AgentRole>,
    results: Vec<AgentResult>,
}

impl MetaAgent {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sub_agents: vec![
                AgentRole::StaticAnalysis,
                AgentRole::LlmSemanticAnalysis,
                AgentRole::ExploitGeneration,
            ],
            results: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_role(role: AgentRole) -> Self {
        let mut agent = Self::new();
        agent.sub_agents = vec![role];
        agent
    }

    pub fn add_sub_agent(&mut self, role: AgentRole) {
        if !self.sub_agents.contains(&role) {
            self.sub_agents.push(role);
        }
    }

    #[must_use]
    pub fn sub_agents(&self) -> &[AgentRole] {
        &self.sub_agents
    }

    pub fn record_result(&mut self, result: AgentResult) {
        self.results.push(result);
    }

    #[must_use]
    pub fn results(&self) -> &[AgentResult] {
        &self.results
    }

    pub fn clear_results(&mut self) {
        self.results.clear();
    }

    #[must_use]
    pub fn successful_results(&self) -> Vec<&AgentResult> {
        self.results.iter().filter(|r| r.success).collect()
    }

    #[must_use]
    pub fn all_findings(&self) -> Vec<&AgentFinding> {
        self.successful_results()
            .iter()
            .flat_map(|r| r.findings.iter())
            .collect()
    }

    /// Cross-validates findings: finds findings reported by multiple agents.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn cross_validate(&self) -> Vec<ValidatedFinding> {
        let mut finding_map: HashMap<String, ValidatedFinding> = HashMap::new();

        for result in self.successful_results() {
            for finding in &result.findings {
                let key = finding.title.to_lowercase();
                let entry = finding_map.entry(key).or_insert_with(|| ValidatedFinding {
                    title: finding.title.clone(),
                    description: finding.description.clone(),
                    severity: finding.severity.clone(),
                    confidence: 0.0,
                    supporting_agents: Vec::new(),
                    evidence: Vec::new(),
                    validation_score: 0.0,
                });

                if !entry.supporting_agents.contains(&finding.agent) {
                    entry.supporting_agents.push(finding.agent);
                }
                entry.evidence.extend(finding.evidence.clone());
                entry.confidence = entry.confidence.max(finding.confidence);
            }
        }

        #[allow(clippy::cast_precision_loss)]
        let total_agents = self.sub_agents.len() as f64;

        let mut validated: Vec<ValidatedFinding> = finding_map
            .into_values()
            .map(|mut v| {
                let support_ratio = v.supporting_agents.len() as f64 / total_agents;
                v.validation_score = support_ratio * v.confidence;
                v
            })
            .collect();

        validated.sort_by(|a, b| {
            b.validation_score
                .partial_cmp(&a.validation_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        validated
    }
}

impl Default for MetaAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_role_names() {
        assert_eq!(AgentRole::StaticAnalysis.name(), "StaticAnalysis");
        assert_eq!(AgentRole::LlmSemanticAnalysis.name(), "LlmSemanticAnalysis");
        assert_eq!(AgentRole::ExploitGeneration.name(), "ExploitGeneration");
        assert_eq!(AgentRole::CrossValidator.name(), "CrossValidator");
    }

    #[test]
    fn test_agent_role_descriptions() {
        assert!(!AgentRole::StaticAnalysis.description().is_empty());
        assert!(!AgentRole::LlmSemanticAnalysis.description().is_empty());
        assert!(!AgentRole::ExploitGeneration.description().is_empty());
    }

    #[test]
    fn test_meta_agent_new() {
        let agent = MetaAgent::new();
        assert_eq!(agent.sub_agents().len(), 3);
        assert!(agent.results().is_empty());
    }

    #[test]
    fn test_meta_agent_default() {
        let agent = MetaAgent::default();
        assert_eq!(agent.sub_agents().len(), 3);
    }

    #[test]
    fn test_meta_agent_with_role() {
        let agent = MetaAgent::with_role(AgentRole::StaticAnalysis);
        assert_eq!(agent.sub_agents().len(), 1);
        assert_eq!(agent.sub_agents()[0], AgentRole::StaticAnalysis);
    }

    #[test]
    fn test_meta_agent_add_sub_agent() {
        let mut agent = MetaAgent::new();
        agent.add_sub_agent(AgentRole::CrossValidator);
        assert_eq!(agent.sub_agents().len(), 4);
        agent.add_sub_agent(AgentRole::CrossValidator);
        assert_eq!(agent.sub_agents().len(), 4);
    }

    #[test]
    fn test_meta_agent_record_result() {
        let mut agent = MetaAgent::new();
        agent.record_result(AgentResult {
            role: AgentRole::StaticAnalysis,
            findings: vec![],
            analysis_time_ms: 100,
            success: true,
            error: None,
        });
        assert_eq!(agent.results().len(), 1);
        assert!(agent.successful_results().len() == 1);
    }

    #[test]
    fn test_meta_agent_all_findings() {
        let mut agent = MetaAgent::new();
        agent.record_result(AgentResult {
            role: AgentRole::StaticAnalysis,
            findings: vec![AgentFinding {
                agent: AgentRole::StaticAnalysis,
                title: "SQL Injection".into(),
                description: "User input in query".into(),
                severity: "High".into(),
                confidence: 0.9,
                evidence: vec!["line 42".into()],
            }],
            analysis_time_ms: 100,
            success: true,
            error: None,
        });
        agent.record_result(AgentResult {
            role: AgentRole::LlmSemanticAnalysis,
            findings: vec![AgentFinding {
                agent: AgentRole::LlmSemanticAnalysis,
                title: "SQL Injection".into(),
                description: "User input in query".into(),
                severity: "High".into(),
                confidence: 0.85,
                evidence: vec!["semantic analysis".into()],
            }],
            analysis_time_ms: 200,
            success: true,
            error: None,
        });

        let findings = agent.all_findings();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_cross_validate() {
        let mut agent = MetaAgent::new();
        agent.record_result(AgentResult {
            role: AgentRole::StaticAnalysis,
            findings: vec![AgentFinding {
                agent: AgentRole::StaticAnalysis,
                title: "Buffer Overflow".into(),
                description: "Unchecked memcpy".into(),
                severity: "Critical".into(),
                confidence: 0.95,
                evidence: vec!["memcpy call".into()],
            }],
            analysis_time_ms: 100,
            success: true,
            error: None,
        });
        agent.record_result(AgentResult {
            role: AgentRole::LlmSemanticAnalysis,
            findings: vec![
                AgentFinding {
                    agent: AgentRole::LlmSemanticAnalysis,
                    title: "Buffer Overflow".into(),
                    description: "Unchecked memcpy".into(),
                    severity: "Critical".into(),
                    confidence: 0.90,
                    evidence: vec!["LLM analysis".into()],
                },
                AgentFinding {
                    agent: AgentRole::LlmSemanticAnalysis,
                    title: "XSS".into(),
                    description: "Unescaped output".into(),
                    severity: "Medium".into(),
                    confidence: 0.70,
                    evidence: vec!["template rendering".into()],
                },
            ],
            analysis_time_ms: 200,
            success: true,
            error: None,
        });

        let validated = agent.cross_validate();
        assert_eq!(validated.len(), 2);

        let bo = validated.iter().find(|v| v.title == "Buffer Overflow").unwrap();
        assert_eq!(bo.supporting_agents.len(), 2);
        assert!(bo.validation_score > 0.0);

        let xss = validated.iter().find(|v| v.title == "XSS").unwrap();
        assert_eq!(xss.supporting_agents.len(), 1);
    }

    #[test]
    fn test_cross_validate_empty() {
        let agent = MetaAgent::new();
        let validated = agent.cross_validate();
        assert!(validated.is_empty());
    }

    #[test]
    fn test_failed_results_excluded() {
        let mut agent = MetaAgent::new();
        agent.record_result(AgentResult {
            role: AgentRole::StaticAnalysis,
            findings: vec![],
            analysis_time_ms: 100,
            success: false,
            error: Some("timeout".into()),
        });
        assert!(agent.successful_results().is_empty());
        assert!(agent.all_findings().is_empty());
    }

    #[test]
    fn test_clear_results() {
        let mut agent = MetaAgent::new();
        agent.record_result(AgentResult {
            role: AgentRole::StaticAnalysis,
            findings: vec![],
            analysis_time_ms: 100,
            success: true,
            error: None,
        });
        assert_eq!(agent.results().len(), 1);
        agent.clear_results();
        assert!(agent.results().is_empty());
    }
}
