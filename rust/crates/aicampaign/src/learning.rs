use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureEvent {
    pub exploit_type: String,
    pub target_os: String,
    pub target_service: String,
    pub failure_reason: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedStrategy {
    pub exploit_type: String,
    pub success_count: usize,
    pub failure_count: usize,
    pub success_rate: f64,
    pub recommended_approach: String,
    pub avoid_conditions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningResult {
    pub total_attempts: usize,
    pub total_successes: usize,
    pub total_failures: usize,
    pub strategies: Vec<LearnedStrategy>,
    pub adjusted_approach: Vec<String>,
}

pub struct LearningEngine;

impl Default for LearningEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LearningEngine {
    pub fn new() -> Self {
        LearningEngine
    }

    pub fn analyze(failures: &[FailureEvent]) -> LearningResult {
        let mut stats: HashMap<String, (usize, usize, Vec<String>)> = HashMap::new();

        for failure in failures {
            let entry = stats.entry(failure.exploit_type.clone()).or_insert((0, 0, Vec::new()));
            entry.1 += 1;
            entry.2.push(failure.failure_reason.clone());
        }

        let mut strategies: Vec<LearnedStrategy> = stats.into_iter().map(|(etype, (successes, failures, reasons))| {
            let total = successes + failures;
            let rate = if total > 0 { successes as f64 / total as f64 } else { 0.0 };
            LearnedStrategy {
                exploit_type: etype.clone(),
                success_count: successes,
                failure_count: failures,
                success_rate: rate,
                recommended_approach: if rate > 0.5 { format!("Continue using {}", etype) } else { format!("Avoid {}; try alternatives", etype) },
                avoid_conditions: reasons,
            }
        }).collect();
        strategies.sort_by(|a, b| b.success_rate.partial_cmp(&a.success_rate).unwrap_or(std::cmp::Ordering::Equal));

        let total = failures.len();
        let successes = failures.iter().filter(|f| f.failure_reason.contains("timeout")).count();
        let failures_count = total - successes;

        let adjusted: Vec<String> = strategies.iter().map(|s| s.recommended_approach.clone()).collect();

        LearningResult {
            total_attempts: total,
            total_successes: successes,
            total_failures: failures_count,
            strategies,
            adjusted_approach: adjusted,
        }
    }

    pub fn update_model(failures: &[FailureEvent]) -> Vec<String> {
        let mut insights = Vec::new();
        let mut patterns: HashMap<&str, usize> = HashMap::new();

        for failure in failures {
            *patterns.entry(failure.target_service.as_str()).or_insert(0) += 1;
        }

        for (service, count) in &patterns {
            if *count > 1 {
                insights.push(format!("Service '{}' is resistant to current approaches ({} failures)", service, count));
            }
        }
        insights
    }

    pub fn suggest_alternative(exploit_type: &str) -> &'static str {
        match exploit_type {
            "SQLi" => "Try NoSQL injection or ORM manipulation",
            "RCE" => "Use deserialization attack or file upload bypass",
            "XSS" => "Try DOM clobbering or mXSS variants",
            "LFI" => "Use PHP wrappers or log poisoning",
            _ => "Research CVEs for target technology stack",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze() {
        let failures = vec![
            FailureEvent { exploit_type: "SQLi".to_string(), target_os: "Linux".to_string(), target_service: "nginx".to_string(), failure_reason: "WAF blocked".to_string(), timestamp: "2024-01-01".to_string() },
            FailureEvent { exploit_type: "SQLi".to_string(), target_os: "Linux".to_string(), target_service: "nginx".to_string(), failure_reason: "Parameterized queries".to_string(), timestamp: "2024-01-02".to_string() },
        ];
        let result = LearningEngine::analyze(&failures);
        assert_eq!(result.total_attempts, 2);
        assert!(!result.strategies.is_empty());
    }

    #[test]
    fn test_analyze_empty() {
        let result = LearningEngine::analyze(&[]);
        assert_eq!(result.total_attempts, 0);
    }

    #[test]
    fn test_update_model() {
        let failures = vec![
            FailureEvent { exploit_type: "RCE".to_string(), target_os: "Linux".to_string(), target_service: "Apache".to_string(), failure_reason: "patched".to_string(), timestamp: "".to_string() },
            FailureEvent { exploit_type: "RCE".to_string(), target_os: "Linux".to_string(), target_service: "Apache".to_string(), failure_reason: "patched".to_string(), timestamp: "".to_string() },
        ];
        let insights = LearningEngine::update_model(&failures);
        assert!(!insights.is_empty());
    }

    #[test]
    fn test_suggest_alternative() {
        let alt = LearningEngine::suggest_alternative("SQLi");
        assert!(alt.contains("NoSQL"));
    }

    #[test]
    fn test_learning_serde() {
        let result = LearningEngine::analyze(&[]);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("total_attempts"));
    }
}
