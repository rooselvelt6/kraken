use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{ExploitType, Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraph {
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub entry_nodes: Vec<usize>,
    pub target_nodes: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: usize,
    pub finding_id: String,
    pub description: String,
    pub severity: Severity,
    pub exploit_type: Option<ExploitType>,
    pub file_path: String,
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub from: usize,
    pub to: usize,
    pub condition: String,
    pub likelihood: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub total_likelihood: f32,
    pub max_severity: Severity,
    pub steps: usize,
    pub description: String,
}

pub struct LateralMovement;

impl LateralMovement {
    /// Builds an attack graph from findings, identifying entry and target nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::lateral::LateralMovement;
    /// use vulnscan::{Finding, Severity, DiscoveryMethod, ExploitType};
    /// let f = Finding::new(Severity::Critical, "rce vuln", None, None, None, None, None, 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let graph = LateralMovement::build_attack_graph(&[f]);
    /// assert_eq!(graph.nodes.len(), 1);
    /// assert_eq!(graph.entry_nodes.len(), 1);
    /// ```
    pub fn build_attack_graph(findings: &[Finding]) -> AttackGraph {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut entry_nodes = Vec::new();
        let mut target_nodes = Vec::new();
        let mut id_map: HashMap<String, usize> = HashMap::new();

        for finding in findings {
            let id = nodes.len();
            id_map.insert(finding.id.clone(), id);

            let node = AttackNode {
                id,
                finding_id: finding.id.clone(),
                description: finding.description.clone(),
                severity: finding.severity,
                exploit_type: finding.exploit_type,
                file_path: finding
                    .file_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                line_number: finding.line_number,
            };

            let is_entry = matches!(
                finding.exploit_type,
                Some(ExploitType::RemoteCodeExecution) | Some(ExploitType::AuthenticationBypass)
            ) || finding.severity == Severity::Critical;
            let is_target = matches!(
                finding.exploit_type,
                Some(ExploitType::PrivilegeEscalation) | Some(ExploitType::SandboxEscape)
            );

            if is_entry {
                entry_nodes.push(id);
            }
            if is_target {
                target_nodes.push(id);
            }

            nodes.push(node);
        }

        for from_id in id_map.values() {
            for chained_id in &findings[*from_id].chained_findings {
                if let Some(to_id) = id_map.get(chained_id) {
                    edges.push(AttackEdge {
                        from: *from_id,
                        to: *to_id,
                        condition: format!(
                            "{} -> {}",
                            findings[*from_id].description, findings[*to_id].description
                        ),
                        likelihood: 0.5,
                    });
                }
            }
        }

        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    let can_chain = Self::can_chain(&nodes[i], &nodes[j]);
                    if can_chain && !edges.iter().any(|e| e.from == i && e.to == j) {
                        edges.push(AttackEdge {
                            from: i,
                            to: j,
                            condition: format!(
                                "{} puede pivotar a {}",
                                nodes[i].description, nodes[j].description
                            ),
                            likelihood: Self::estimate_likelihood(&nodes[i], &nodes[j]),
                        });
                    }
                }
            }
        }

        AttackGraph {
            nodes,
            edges,
            entry_nodes,
            target_nodes,
        }
    }

    /// Finds attack paths from entry nodes to target nodes in the graph.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::lateral::LateralMovement;
    /// use vulnscan::{Finding, Severity, DiscoveryMethod, ExploitType};
    /// let rce = Finding::new(Severity::Critical, "rce", None, None, None, None, None, 0.9, DiscoveryMethod::StaticPatternMatching)
    ///     .with_exploit("code".to_string(), ExploitType::RemoteCodeExecution);
    /// let privesc = Finding::new(Severity::Critical, "privesc", None, None, None, None, None, 0.9, DiscoveryMethod::StaticPatternMatching)
    ///     .with_exploit("code".to_string(), ExploitType::PrivilegeEscalation);
    /// let mut rce2 = rce.clone();
    /// rce2.chained_findings.push(privesc.id.clone());
    /// let mut privesc2 = privesc.clone();
    /// let graph = LateralMovement::build_attack_graph(&[rce2, privesc2]);
    /// let paths = LateralMovement::find_attack_paths(&graph);
    /// ```
    pub fn find_attack_paths(graph: &AttackGraph) -> Vec<AttackPath> {
        let mut paths = Vec::new();

        for &entry in &graph.entry_nodes {
            for &target in &graph.target_nodes {
                if entry == target {
                    continue;
                }
                if let Some(path) = Self::bfs_shortest_path(graph, entry, target) {
                    paths.push(path);
                }
            }
        }

        if paths.is_empty() {
            for &entry in &graph.entry_nodes {
                let reachable = Self::bfs_reachable(graph, entry);
                if !reachable.is_empty() {
                    let target = reachable[0];
                    if let Some(path) = Self::bfs_shortest_path(graph, entry, target) {
                        paths.push(path);
                    }
                }
            }
        }

        paths.sort_by(|a, b| {
            b.max_severity
                .value()
                .cmp(&a.max_severity.value())
                .then_with(|| {
                    b.total_likelihood
                        .partial_cmp(&a.total_likelihood)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        paths
    }

    /// Returns finding IDs that are disconnected from the attack graph.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::lateral::LateralMovement;
    /// use vulnscan::{Finding, Severity, DiscoveryMethod};
    /// let f = Finding::new(Severity::Low, "isolated", None, None, None, None, None, 0.3, DiscoveryMethod::StaticPatternMatching);
    /// let graph = LateralMovement::build_attack_graph(&[f]);
    /// let orphans = LateralMovement::deorphan_findings(&graph);
    /// assert_eq!(orphans.len(), 1);
    /// ```
    pub fn deorphan_findings(graph: &AttackGraph) -> Vec<String> {
        let connected: std::collections::HashSet<usize> = graph
            .edges
            .iter()
            .flat_map(|e| vec![e.from, e.to])
            .collect();

        graph
            .nodes
            .iter()
            .filter(|n| !connected.contains(&n.id) && !graph.entry_nodes.contains(&n.id))
            .map(|n| n.finding_id.clone())
            .collect()
    }

    fn can_chain(from: &AttackNode, to: &AttackNode) -> bool {
        let from_exploitable = from.exploit_type.is_some() || from.severity.value() >= 2;
        let to_reachable = to.exploit_type == Some(ExploitType::PrivilegeEscalation)
            || to.severity == Severity::Critical
            || to.exploit_type == Some(ExploitType::RemoteCodeExecution);

        from_exploitable && to_reachable && from.id != to.id
    }

    fn estimate_likelihood(from: &AttackNode, to: &AttackNode) -> f32 {
        let mut score: f32 = 0.3;
        if from.file_path == to.file_path {
            score += 0.2;
        }
        if from.exploit_type == Some(ExploitType::RemoteCodeExecution) {
            score += 0.2;
        }
        if to.exploit_type == Some(ExploitType::PrivilegeEscalation) {
            score += 0.1;
        }
        if from.severity == Severity::Critical {
            score += 0.1;
        }
        if from.severity == Severity::High {
            score += 0.05;
        }
        score.min(1.0)
    }

    fn bfs_shortest_path(graph: &AttackGraph, from: usize, to: usize) -> Option<AttackPath> {
        use std::collections::VecDeque;

        let mut visited = vec![false; graph.nodes.len()];
        let mut parent: Vec<Option<(usize, usize)>> = vec![None; graph.nodes.len()];
        let mut queue = VecDeque::new();

        visited[from] = true;
        queue.push_back(from);

        while let Some(current) = queue.pop_front() {
            if current == to {
                return Some(Self::reconstruct_path(graph, from, to, &parent));
            }

            for (edge_idx, edge) in graph.edges.iter().enumerate() {
                if edge.from == current && !visited[edge.to] {
                    visited[edge.to] = true;
                    parent[edge.to] = Some((current, edge_idx));
                    queue.push_back(edge.to);
                }
            }
        }

        None
    }

    fn bfs_reachable(graph: &AttackGraph, from: usize) -> Vec<usize> {
        let mut visited = vec![false; graph.nodes.len()];
        let mut stack = vec![from];
        visited[from] = true;

        while let Some(current) = stack.pop() {
            for edge in &graph.edges {
                if edge.from == current && !visited[edge.to] {
                    visited[edge.to] = true;
                    stack.push(edge.to);
                }
            }
        }

        visited
            .iter()
            .enumerate()
            .filter(|(i, &v)| v && *i != from)
            .map(|(i, _)| i)
            .collect()
    }

    fn reconstruct_path(
        graph: &AttackGraph,
        from: usize,
        to: usize,
        parent: &[Option<(usize, usize)>],
    ) -> AttackPath {
        let mut path_nodes = Vec::new();
        let mut path_edges = Vec::new();
        let mut current = to;

        while current != from {
            if let Some((prev, edge_idx)) = parent[current] {
                path_nodes.push(graph.nodes[current].clone());
                path_edges.push(graph.edges[edge_idx].clone());
                current = prev;
            } else {
                break;
            }
        }
        path_nodes.push(graph.nodes[from].clone());
        path_nodes.reverse();
        path_edges.reverse();

        let likelihood: f32 = path_edges.iter().map(|e| e.likelihood).product();
        let max_sev = path_nodes
            .iter()
            .map(|n| n.severity)
            .max()
            .unwrap_or(Severity::Info);
        let steps = path_nodes.len();
        let desc = path_nodes
            .iter()
            .map(|n| n.description.clone())
            .collect::<Vec<_>>()
            .join(" -> ");

        AttackPath {
            nodes: path_nodes,
            edges: path_edges,
            total_likelihood: likelihood,
            max_severity: max_sev,
            steps,
            description: format!("Attack path: {}", desc),
        }
    }
}
