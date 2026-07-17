use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousResult {
    pub phase: String,
    pub success: bool,
    pub findings: Vec<String>,
    pub time_spent_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveDecision {
    pub next_action: String,
    pub confidence: f64,
    pub reason: String,
    pub alternative_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptationReport {
    pub target: String,
    pub history: Vec<PreviousResult>,
    pub decisions: Vec<AdaptiveDecision>,
    pub adapted_plan: Vec<String>,
    pub learning_progress: f64,
}

pub struct AdaptiveTargeting;

impl Default for AdaptiveTargeting {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveTargeting {
    pub fn new() -> Self {
        AdaptiveTargeting
    }

    pub fn analyze(target: &str, history: &[PreviousResult]) -> AdaptationReport {
        let mut decisions = Vec::new();
        let mut adapted = Vec::new();

        for result in history {
            let decision = if result.success {
                AdaptiveDecision {
                    next_action: format!("Continue to next phase after {}", result.phase),
                    confidence: 0.85,
                    reason: format!("Phase '{}' completed successfully with {} findings", result.phase, result.findings.len()),
                    alternative_actions: vec!["Deepen recon".to_string(), "Try alternative exploits".to_string()],
                }
            } else {
                adapted.push(format!("Retrying {} with adjusted parameters", result.phase));
                AdaptiveDecision {
                    next_action: format!("Retry {} with different approach", result.phase),
                    confidence: 0.45,
                    reason: format!("Phase '{}' failed after {}s, switching strategy", result.phase, result.time_spent_secs),
                    alternative_actions: vec!["Switch to passive recon".to_string(), "Use different toolset".to_string()],
                }
            };
            decisions.push(decision);
        }

        let progress = if history.is_empty() {
            0.0
        } else {
            history.iter().filter(|r| r.success).count() as f64 / history.len() as f64
        };

        AdaptationReport {
            target: target.to_string(),
            history: history.to_vec(),
            decisions,
            adapted_plan: adapted,
            learning_progress: progress,
        }
    }

    pub fn next_action_probabilities(history: &[PreviousResult]) -> HashMap<String, f64> {
        let mut probs = HashMap::new();
        if history.is_empty() {
            probs.insert("reconnaissance".to_string(), 0.9);
            probs.insert("exploitation".to_string(), 0.1);
        } else {
            let success_rate: f64 = history.iter().filter(|r| r.success).count() as f64 / history.len() as f64;
            probs.insert("exploitation".to_string(), 0.5 + success_rate * 0.4);
            probs.insert("post_exploitation".to_string(), success_rate * 0.5);
            probs.insert("pivoting".to_string(), success_rate * 0.3);
        }
        probs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze() {
        let history = vec![
            PreviousResult { phase: "Recon".to_string(), success: true, findings: vec!["port 80".to_string()], time_spent_secs: 30 },
            PreviousResult { phase: "Exploit".to_string(), success: false, findings: vec![], time_spent_secs: 60 },
        ];
        let report = AdaptiveTargeting::analyze("10.0.0.1", &history);
        assert_eq!(report.history.len(), 2);
        assert_eq!(report.decisions.len(), 2);
        assert!(!report.adapted_plan.is_empty());
    }

    #[test]
    fn test_analyze_empty() {
        let report = AdaptiveTargeting::analyze("10.0.0.1", &[]);
        assert!(report.decisions.is_empty());
        assert_eq!(report.learning_progress, 0.0);
    }

    #[test]
    fn test_next_action_probabilities() {
        let history = vec![
            PreviousResult { phase: "Scan".to_string(), success: true, findings: vec![], time_spent_secs: 10 },
        ];
        let probs = AdaptiveTargeting::next_action_probabilities(&history);
        assert!(probs.contains_key("exploitation"));
    }

    #[test]
    fn test_next_action_probabilities_empty() {
        let probs = AdaptiveTargeting::next_action_probabilities(&[]);
        assert_eq!(probs.get("reconnaissance"), Some(&0.9));
    }

    #[test]
    fn test_adaptive_serde() {
        let report = AdaptiveTargeting::analyze("test.local", &[]);
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("learning_progress"));
    }
}
