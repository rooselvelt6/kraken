use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub nodes: Vec<DependencyNode>,
    pub edges: Vec<DependencyEdge>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    pub name: String,
    pub version: String,
    pub depth: usize,
    pub risk_score: f64,
    pub vulnerabilities: Vec<String>,
    pub age_days: u64,
    pub last_maintained_days: u64,
    pub maintainers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub source: String,
    pub target: String,
    pub dependency_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub total_dependencies: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub high_risk_count: usize,
    pub medium_risk_count: usize,
    pub low_risk_count: usize,
    pub overall_risk_score: f64,
    pub top_risks: Vec<RiskItem>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskItem {
    pub name: String,
    pub version: String,
    pub risk_score: f64,
    pub risk_factors: Vec<String>,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRiskScorer {
    pub age_threshold_low: u64,
    pub age_threshold_high: u64,
    pub maintainer_threshold: usize,
    pub vulnerability_penalty: f64,
}

impl Default for DependencyRiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyRiskScorer {
    pub fn new() -> Self {
        DependencyRiskScorer {
            age_threshold_low: 180,
            age_threshold_high: 365,
            maintainer_threshold: 2,
            vulnerability_penalty: 0.3,
        }
    }

    pub fn build_graph(packages: &[(&str, &str)], dependencies: &[(&str, &str)]) -> DependencyGraph {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut depth_map = HashMap::new();

        for (name, version) in packages {
            nodes.push(DependencyNode {
                name: name.to_string(),
                version: version.to_string(),
                depth: 0,
                risk_score: 0.0,
                vulnerabilities: Vec::new(),
                age_days: 0,
                last_maintained_days: 0,
                maintainers: 1,
            });
            depth_map.insert(name.to_string(), 0);
        }

        for (source, target) in dependencies {
            edges.push(DependencyEdge {
                source: source.to_string(),
                target: target.to_string(),
                dependency_type: "direct".to_string(),
            });

            let source_depth = depth_map.get(*source).copied().unwrap_or(0);
            let target_depth = source_depth + 1;
            depth_map.insert(target.to_string(), target_depth);

            if !nodes.iter().any(|n| n.name == *target) {
                nodes.push(DependencyNode {
                    name: target.to_string(),
                    version: "unknown".to_string(),
                    depth: target_depth,
                    risk_score: 0.0,
                    vulnerabilities: Vec::new(),
                    age_days: 0,
                    last_maintained_days: 0,
                    maintainers: 0,
                });
            }
        }

        DependencyGraph {
            nodes,
            edges,
            root: dependencies.first().map(|(s, _)| s.to_string()).unwrap_or_default(),
        }
    }

    pub fn calculate_risk_score(node: &DependencyNode, scorer: &DependencyRiskScorer) -> f64 {
        let mut score = 0.0;

        if node.age_days > scorer.age_threshold_high {
            score += 0.3;
        } else if node.age_days > scorer.age_threshold_low {
            score += 0.1;
        }

        if node.maintainers < scorer.maintainer_threshold {
            score += 0.2;
        }

        if node.last_maintained_days > 365 {
            score += 0.2;
        }

        score += node.vulnerabilities.len() as f64 * scorer.vulnerability_penalty;

        if node.depth > 3 {
            score += 0.1;
        }

        score.min(1.0)
    }

    pub fn analyze_risks(graph: &DependencyGraph, scorer: &DependencyRiskScorer) -> RiskReport {
        let mut analyzed_nodes = graph.nodes.clone();
        let mut high_risk = 0;
        let mut medium_risk = 0;
        let mut low_risk = 0;
        let mut risk_items = Vec::new();

        for node in &mut analyzed_nodes {
            node.risk_score = Self::calculate_risk_score(node, scorer);
            
            match node.risk_score {
                s if s >= 0.7 => high_risk += 1,
                s if s >= 0.4 => medium_risk += 1,
                _ => low_risk += 1,
            }

            if node.risk_score >= 0.4 {
                let mut factors = Vec::new();
                if node.age_days > scorer.age_threshold_high {
                    factors.push("Old package".to_string());
                }
                if node.maintainers < scorer.maintainer_threshold {
                    factors.push("Few maintainers".to_string());
                }
                if !node.vulnerabilities.is_empty() {
                    factors.push(format!("{} vulnerabilities", node.vulnerabilities.len()));
                }
                if node.last_maintained_days > 365 {
                    factors.push("Not recently maintained".to_string());
                }

                risk_items.push(RiskItem {
                    name: node.name.clone(),
                    version: node.version.clone(),
                    risk_score: node.risk_score,
                    risk_factors: factors,
                    depth: node.depth,
                });
            }
        }

        risk_items.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

        let total = analyzed_nodes.len();
        let direct = analyzed_nodes.iter().filter(|n| n.depth == 1).count();
        let transitive = total - direct;
        let overall = analyzed_nodes.iter().map(|n| n.risk_score).sum::<f64>() / total as f64;

        let mut recommendations = Vec::new();
        if high_risk > 0 {
            recommendations.push(format!("Review {} high-risk dependencies", high_risk));
        }
        if transitive > direct * 2 {
            recommendations.push("Consider reducing transitive dependencies".to_string());
        }

        RiskReport {
            total_dependencies: total,
            direct_dependencies: direct,
            transitive_dependencies: transitive,
            high_risk_count: high_risk,
            medium_risk_count: medium_risk,
            low_risk_count: low_risk,
            overall_risk_score: overall,
            top_risks: risk_items.into_iter().take(10).collect(),
            recommendations,
        }
    }

    pub fn find_transitive_deps(graph: &DependencyGraph, start: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back(start.to_string());
        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            result.push(current.clone());

            for edge in &graph.edges {
                if edge.source == current && !visited.contains(&edge.target) {
                    queue.push_back(edge.target.clone());
                }
            }
        }

        result
    }

    pub fn visualize_graph(graph: &DependencyGraph) -> String {
        let mut output = String::new();
        output.push_str("Dependency Graph:\n");
        output.push_str("================\n");

        for node in &graph.nodes {
            let indent = "  ".repeat(node.depth);
            let risk_indicator = match node.risk_score {
                s if s >= 0.7 => " [HIGH RISK]",
                s if s >= 0.4 => " [MEDIUM RISK]",
                _ => "",
            };
            output.push_str(&format!("{}├── {}@{}{}\n", indent, node.name, node.version, risk_indicator));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> DependencyGraph {
        let packages = vec![
            ("app", "1.0.0"),
            ("serde", "1.0.200"),
            ("reqwest", "0.11.0"),
            ("tokio", "1.0"),
        ];
        let dependencies = vec![
            ("app", "serde"),
            ("app", "reqwest"),
            ("reqwest", "tokio"),
        ];
        DependencyRiskScorer::build_graph(&packages, &dependencies)
    }

    #[test]
    fn test_build_graph() {
        let graph = sample_graph();
        assert_eq!(graph.nodes.len(), 4);
        assert_eq!(graph.edges.len(), 3);
    }

    #[test]
    fn test_risk_score_low() {
        let node = DependencyNode {
            name: "test".to_string(),
            version: "1.0".to_string(),
            depth: 1,
            risk_score: 0.0,
            vulnerabilities: Vec::new(),
            age_days: 30,
            last_maintained_days: 10,
            maintainers: 5,
        };
        let scorer = DependencyRiskScorer::new();
        let score = DependencyRiskScorer::calculate_risk_score(&node, &scorer);
        assert!(score < 0.3);
    }

    #[test]
    fn test_risk_score_high() {
        let node = DependencyNode {
            name: "old-lib".to_string(),
            version: "0.1".to_string(),
            depth: 4,
            risk_score: 0.0,
            vulnerabilities: vec!["CVE-2023-1234".to_string()],
            age_days: 500,
            last_maintained_days: 400,
            maintainers: 1,
        };
        let scorer = DependencyRiskScorer::new();
        let score = DependencyRiskScorer::calculate_risk_score(&node, &scorer);
        assert!(score >= 0.7);
    }

    #[test]
    fn test_analyze_risks() {
        let graph = sample_graph();
        let scorer = DependencyRiskScorer::new();
        let report = DependencyRiskScorer::analyze_risks(&graph, &scorer);
        assert_eq!(report.total_dependencies, 4);
        assert!(report.overall_risk_score >= 0.0);
    }

    #[test]
    fn test_find_transitive_deps() {
        let graph = sample_graph();
        let deps = DependencyRiskScorer::find_transitive_deps(&graph, "app");
        assert!(deps.contains(&"app".to_string()));
        assert!(deps.contains(&"serde".to_string()));
        assert!(deps.contains(&"reqwest".to_string()));
        assert!(deps.contains(&"tokio".to_string()));
    }

    #[test]
    fn test_visualize_graph() {
        let graph = sample_graph();
        let viz = DependencyRiskScorer::visualize_graph(&graph);
        assert!(viz.contains("Dependency Graph"));
        assert!(viz.contains("app@1.0.0"));
    }

    #[test]
    fn test_risk_report_structure() {
        let graph = sample_graph();
        let scorer = DependencyRiskScorer::new();
        let report = DependencyRiskScorer::analyze_risks(&graph, &scorer);
        assert_eq!(report.total_dependencies, report.direct_dependencies + report.transitive_dependencies);
        assert_eq!(report.high_risk_count + report.medium_risk_count + report.low_risk_count, report.total_dependencies);
    }

    #[test]
    fn test_dependency_node_serialization() {
        let node = DependencyNode {
            name: "test".to_string(),
            version: "1.0".to_string(),
            depth: 0,
            risk_score: 0.5,
            vulnerabilities: Vec::new(),
            age_days: 100,
            last_maintained_days: 50,
            maintainers: 2,
        };
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("1.0"));
    }
}