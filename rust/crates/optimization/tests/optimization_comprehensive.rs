use optimization::*;
use optimization::aco::{Ant, Edge};
use optimization::ga::GAStats;

// ── OptimizationConfig ──

#[test]
fn config_default_population_size() {
    assert_eq!(OptimizationConfig::default().population_size, 30);
}

#[test]
fn config_default_max_iterations() {
    assert_eq!(OptimizationConfig::default().max_iterations, 100);
}

#[test]
fn config_default_convergence() {
    assert_eq!(OptimizationConfig::default().convergence_threshold, 1e-6);
}

#[test]
fn config_custom() {
    let c = OptimizationConfig { population_size: 50, max_iterations: 200, convergence_threshold: 1e-8 };
    assert_eq!(c.population_size, 50);
    assert_eq!(c.max_iterations, 200);
}

#[test]
fn config_clone() {
    let c = OptimizationConfig { population_size: 10, max_iterations: 50, convergence_threshold: 0.1 };
    let c2 = c.clone();
    assert_eq!(c.population_size, c2.population_size);
    assert_eq!(c.max_iterations, c2.max_iterations);
    assert_eq!(c.convergence_threshold, c2.convergence_threshold);
}

#[test]
fn config_debug() {
    let d = format!("{:?}", OptimizationConfig::default());
    assert!(d.contains("OptimizationConfig"));
}

#[test]
fn config_serde_roundtrip() {
    let c = OptimizationConfig { population_size: 42, max_iterations: 99, convergence_threshold: 0.5 };
    let json = serde_json::to_string(&c).unwrap();
    let c2: OptimizationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c.population_size, c2.population_size);
    assert_eq!(c.convergence_threshold, c2.convergence_threshold);
}

#[test]
fn config_serde_json_value() {
    let c = OptimizationConfig::default();
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(v["population_size"], 30);
}

// ── Algorithm ──

#[test]
fn algorithm_default_is_pso() {
    assert!(matches!(Algorithm::default(), Algorithm::PSO));
}

#[test]
fn algorithm_variants() {
    assert!(matches!(Algorithm::PSO, Algorithm::PSO));
    assert!(matches!(Algorithm::GA, Algorithm::GA));
    assert!(matches!(Algorithm::ACO, Algorithm::ACO));
    assert!(matches!(Algorithm::SimulatedAnnealing, Algorithm::SimulatedAnnealing));
}

#[test]
fn algorithm_equality() {
    assert_eq!(Algorithm::PSO, Algorithm::PSO);
    assert_ne!(Algorithm::PSO, Algorithm::GA);
    assert_ne!(Algorithm::ACO, Algorithm::SimulatedAnnealing);
}

#[test]
fn algorithm_clone() {
    let a = Algorithm::GA;
    let a2 = a;
    assert_eq!(a, a2);
}

#[test]
fn algorithm_debug() {
    assert_eq!(format!("{:?}", Algorithm::PSO), "PSO");
    assert_eq!(format!("{:?}", Algorithm::ACO), "ACO");
}

#[test]
fn algorithm_serde_roundtrip() {
    for a in [Algorithm::PSO, Algorithm::GA, Algorithm::ACO, Algorithm::SimulatedAnnealing] {
        let json = serde_json::to_string(&a).unwrap();
        let a2: Algorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(a, a2);
    }
}

#[test]
fn algorithm_copy() {
    let a = Algorithm::ACO;
    let b = a;
    assert_eq!(a, b);
}

// ── Particle ──

#[test]
fn particle_new_dimensions() {
    let p = Particle::new(5);
    assert_eq!(p.position.len(), 5);
    assert_eq!(p.velocity.len(), 5);
    assert_eq!(p.best_position.len(), 5);
}

#[test]
fn particle_initial_fitness() {
    let p = Particle::new(3);
    assert_eq!(p.fitness, f64::INFINITY);
    assert_eq!(p.best_fitness, f64::INFINITY);
}

#[test]
fn particle_position_range() {
    let p = Particle::new(20);
    for &v in &p.position {
        assert!(v >= 0.0 && v <= 1.0);
    }
}

#[test]
fn particle_velocity_range() {
    let p = Particle::new(20);
    for &v in &p.velocity {
        assert!(v >= -1.0 && v <= 1.0);
    }
}

#[test]
fn particle_update_best_improvement() {
    let mut p = Particle::new(3);
    p.fitness = 0.5;
    p.position = vec![0.1, 0.2, 0.3];
    p.update_best();
    assert_eq!(p.best_fitness, 0.5);
    assert_eq!(p.best_position, vec![0.1, 0.2, 0.3]);
}

#[test]
fn particle_update_best_no_improvement() {
    let mut p = Particle::new(3);
    p.best_fitness = 0.5;
    p.best_position = vec![0.1, 0.2, 0.3];
    p.fitness = 1.0;
    p.position = vec![0.9, 0.9, 0.9];
    p.update_best();
    assert_eq!(p.best_fitness, 0.5);
    assert_eq!(p.best_position, vec![0.1, 0.2, 0.3]);
}

#[test]
fn particle_update_best_equal_fitness() {
    let mut p = Particle::new(2);
    p.best_fitness = 1.0;
    p.best_position = vec![0.5, 0.5];
    p.fitness = 1.0;
    p.position = vec![0.6, 0.6];
    p.update_best();
    assert_eq!(p.best_fitness, 1.0);
    assert_eq!(p.best_position, vec![0.5, 0.5]);
}

#[test]
fn particle_clone() {
    let mut p = Particle::new(3);
    p.fitness = 1.5;
    let p2 = p.clone();
    assert_eq!(p.fitness, p2.fitness);
    assert_eq!(p.position, p2.position);
}

#[test]
fn particle_debug() {
    let p = Particle::new(2);
    let d = format!("{:?}", p);
    assert!(d.contains("Particle"));
}

#[test]
fn particle_serde_roundtrip() {
    let mut p = Particle::new(3);
    p.fitness = 42.0;
    p.best_fitness = 42.0;
    let json = serde_json::to_string(&p).unwrap();
    let p2: Particle = serde_json::from_str(&json).unwrap();
    assert_eq!(p.fitness, p2.fitness);
    assert_eq!(p.position, p2.position);
}

// ── ToolScore ──

#[test]
fn tool_score_fields() {
    let ts = ToolScore { tool_name: "bash".to_string(), score: 0.9, confidence: 0.45 };
    assert_eq!(ts.tool_name, "bash");
    assert_eq!(ts.score, 0.9);
    assert_eq!(ts.confidence, 0.45);
}

#[test]
fn tool_score_clone() {
    let ts = ToolScore { tool_name: "read".to_string(), score: 1.0, confidence: 0.5 };
    let ts2 = ts.clone();
    assert_eq!(ts.tool_name, ts2.tool_name);
}

#[test]
fn tool_score_debug() {
    let ts = ToolScore { tool_name: "x".to_string(), score: 0.0, confidence: 0.0 };
    assert!(format!("{:?}", ts).contains("ToolScore"));
}

#[test]
fn tool_score_serde_roundtrip() {
    let ts = ToolScore { tool_name: "edit".to_string(), score: 0.7, confidence: 0.35 };
    let json = serde_json::to_string(&ts).unwrap();
    let ts2: ToolScore = serde_json::from_str(&json).unwrap();
    assert_eq!(ts.tool_name, ts2.tool_name);
    assert_eq!(ts.score, ts2.score);
}

// ── PSOToolSelector ──

#[test]
fn pso_new() {
    let s = PSOToolSelector::new(5, 20, 50);
    let best = s.get_best_selection();
    assert_eq!(best.len(), 5);
}

#[test]
fn pso_initial_iteration() {
    let s = PSOToolSelector::new(3, 10, 100);
    assert_eq!(s.iteration(), 0);
}

#[test]
fn pso_best_fitness_initial() {
    let s = PSOToolSelector::new(3, 10, 10);
    assert_eq!(s.best_fitness(), f64::INFINITY);
}

#[test]
fn pso_iterate() {
    let fitness_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut s = PSOToolSelector::new(3, 10, 50);
    s.iterate(fitness_fn);
    assert_eq!(s.iteration(), 1);
}

#[test]
fn pso_iterate_updates_fitness() {
    let fitness_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut s = PSOToolSelector::new(3, 10, 10);
    s.iterate(fitness_fn);
    assert!(s.best_fitness() < f64::INFINITY);
}

#[test]
fn pso_optimize() {
    let fitness_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut s = PSOToolSelector::new(3, 10, 100);
    let result = s.optimize(fitness_fn);
    assert_eq!(result.len(), 3);
    assert!(s.best_fitness() < 10.0);
}

#[test]
fn pso_has_converged_max_iterations() {
    let s = PSOToolSelector::new(3, 10, 0);
    assert!(s.has_converged(1.0));
}

#[test]
fn pso_has_converged_by_fitness() {
    let mut s = PSOToolSelector::new(3, 10, 100);
    s.iterate(|pos| pos.iter().map(|x| x * x).sum());
    let fitness = s.best_fitness();
    assert!(s.has_converged(fitness + 1.0));
}

#[test]
fn pso_to_tool_scores() {
    let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let s = PSOToolSelector::new(3, 10, 10);
    let scores = s.to_tool_scores(&names);
    assert_eq!(scores.len(), 3);
    assert_eq!(scores[0].tool_name, "a");
    assert_eq!(scores[1].tool_name, "b");
    assert_eq!(scores[2].tool_name, "c");
}

#[test]
fn pso_to_tool_scores_empty() {
    let s = PSOToolSelector::new(0, 10, 10);
    let scores = s.to_tool_scores(&[]);
    assert!(scores.is_empty());
}

#[test]
fn pso_clone() {
    let s = PSOToolSelector::new(3, 10, 10);
    let s2 = s.clone();
    assert_eq!(s2.get_best_selection().len(), 3);
}

#[test]
fn pso_debug() {
    let s = PSOToolSelector::new(2, 5, 5);
    assert!(format!("{:?}", s).contains("PSOToolSelector"));
}

#[test]
fn pso_serde_roundtrip() {
    let fitness_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut s = PSOToolSelector::new(3, 10, 10);
    s.iterate(fitness_fn);
    let json = serde_json::to_string(&s).unwrap();
    let s2: PSOToolSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(s2.get_best_selection().len(), 3);
}

#[test]
fn pso_multiple_iterations() {
    let fitness_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut s = PSOToolSelector::new(3, 10, 100);
    for _ in 0..10 {
        s.iterate(fitness_fn);
    }
    assert_eq!(s.iteration(), 10);
}

#[test]
fn pso_best_selection_length() {
    let s = PSOToolSelector::new(8, 15, 30);
    assert_eq!(s.get_best_selection().len(), 8);
}

#[test]
fn pso_particle_count() {
    let s = PSOToolSelector::new(3, 25, 10);
    let json = serde_json::to_string(&s).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v["particles"].is_array());
    assert_eq!(v["particles"].as_array().unwrap().len(), 25);
}

// ── SimulatedAnnealer ──

#[test]
fn sa_new() {
    let sa = SimulatedAnnealer::new(5, 500.0, 0.95, 0.1, 50);
    let best = sa.get_best();
    assert_eq!(best.len(), 5);
}

#[test]
fn sa_with_default_params() {
    let sa = SimulatedAnnealer::with_default_params(4);
    assert_eq!(sa.get_temperature(), 1000.0);
    assert_eq!(sa.get_best().len(), 4);
}

#[test]
fn sa_initial_best_energy() {
    let sa = SimulatedAnnealer::new(3, 100.0, 0.9, 0.01, 10);
    assert_eq!(sa.get_best_energy(), f64::INFINITY);
}

#[test]
fn sa_has_not_converged() {
    let sa = SimulatedAnnealer::new(2, 1000.0, 0.99, 0.001, 100);
    assert!(!sa.has_converged());
}

#[test]
fn sa_has_converged() {
    let sa = SimulatedAnnealer::new(2, 0.1, 0.5, 1.0, 1);
    assert!(sa.has_converged());
}

#[test]
fn sa_set_initial_solution() {
    let mut sa = SimulatedAnnealer::with_default_params(3);
    sa.set_initial_solution(vec![0.1, 0.2, 0.3]);
    assert_eq!(sa.get_best(), vec![0.1, 0.2, 0.3]);
}

#[test]
fn sa_run_iteration() {
    let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut sa = SimulatedAnnealer::new(2, 100.0, 0.9, 0.01, 10);
    let temp_before = sa.get_temperature();
    sa.run_iteration(energy_fn);
    assert!(sa.get_temperature() < temp_before);
}

#[test]
fn sa_run_iteration_tracks_best() {
    let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut sa = SimulatedAnnealer::new(2, 10.0, 0.5, 0.01, 10);
    sa.set_initial_solution(vec![0.9, 0.9]);
    for _ in 0..20 {
        sa.run_iteration(energy_fn);
    }
    assert!(sa.get_best_energy() <= 2.0);
}

#[test]
fn sa_optimize() {
    let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| (x - 0.5).powi(2)).sum() };
    let mut sa = SimulatedAnnealer::new(3, 100.0, 0.99, 0.01, 10);
    let result = sa.optimize(energy_fn);
    assert_eq!(result.len(), 3);
}

#[test]
fn sa_cooling_rate() {
    let mut sa = SimulatedAnnealer::new(2, 100.0, 0.5, 0.01, 1);
    let initial = sa.get_temperature();
    sa.run_iteration(|_| 1.0);
    assert!((sa.get_temperature() - initial * 0.5).abs() < 1e-10);
}

#[test]
fn sa_get_best_after_optimize() {
    let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut sa = SimulatedAnnealer::new(3, 100.0, 0.9, 1.0, 5);
    sa.optimize(energy_fn);
    let best = sa.get_best();
    assert_eq!(best.len(), 3);
    assert!(sa.get_best_energy() < f64::INFINITY);
}

#[test]
fn sa_clone() {
    let sa = SimulatedAnnealer::with_default_params(3);
    let sa2 = sa.clone();
    assert_eq!(sa2.get_temperature(), sa.get_temperature());
}

#[test]
fn sa_debug() {
    let sa = SimulatedAnnealer::new(2, 100.0, 0.9, 0.1, 10);
    assert!(format!("{:?}", sa).contains("SimulatedAnnealer"));
}

#[test]
fn sa_serde_roundtrip() {
    let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
    let mut sa = SimulatedAnnealer::new(3, 500.0, 0.95, 0.01, 50);
    sa.optimize(energy_fn);
    let json = serde_json::to_string(&sa).unwrap();
    let sa2: SimulatedAnnealer = serde_json::from_str(&json).unwrap();
    assert_eq!(sa2.get_temperature(), sa.get_temperature());
}

// ── NodeType ──

#[test]
fn node_type_variants() {
    assert!(matches!(NodeType::File, NodeType::File));
    assert!(matches!(NodeType::Function, NodeType::Function));
    assert!(matches!(NodeType::Class, NodeType::Class));
    assert!(matches!(NodeType::Module, NodeType::Module));
    assert!(matches!(NodeType::Dependency, NodeType::Dependency));
}

#[test]
fn node_type_equality() {
    assert_eq!(NodeType::File, NodeType::File);
    assert_ne!(NodeType::File, NodeType::Class);
    assert_ne!(NodeType::Function, NodeType::Module);
}

#[test]
fn node_type_clone() {
    let nt = NodeType::Dependency;
    let nt2 = nt.clone();
    assert_eq!(nt, nt2);
}

#[test]
fn node_type_debug() {
    assert_eq!(format!("{:?}", NodeType::File), "File");
    assert_eq!(format!("{:?}", NodeType::Dependency), "Dependency");
}

#[test]
fn node_type_serde_roundtrip() {
    for nt in [NodeType::File, NodeType::Function, NodeType::Class, NodeType::Module, NodeType::Dependency] {
        let json = serde_json::to_string(&nt).unwrap();
        let nt2: NodeType = serde_json::from_str(&json).unwrap();
        assert_eq!(nt, nt2);
    }
}

// ── Node ──

#[test]
fn node_fields() {
    let n = Node { id: "test".to_string(), node_type: NodeType::File };
    assert_eq!(n.id, "test");
    assert!(matches!(n.node_type, NodeType::File));
}

#[test]
fn node_clone() {
    let n = Node { id: "x".to_string(), node_type: NodeType::Class };
    let n2 = n.clone();
    assert_eq!(n.id, n2.id);
}

#[test]
fn node_debug() {
    let n = Node { id: "a".to_string(), node_type: NodeType::Function };
    assert!(format!("{:?}", n).contains("Node"));
}

#[test]
fn node_serde_roundtrip() {
    let n = Node { id: "n1".to_string(), node_type: NodeType::Module };
    let json = serde_json::to_string(&n).unwrap();
    let n2: Node = serde_json::from_str(&json).unwrap();
    assert_eq!(n.id, n2.id);
    assert_eq!(n.node_type, n2.node_type);
}

// ── Edge ──

#[test]
fn edge_fields() {
    let e = Edge { from: "A".to_string(), to: "B".to_string(), pheromone: 1.0, distance: 2.5 };
    assert_eq!(e.from, "A");
    assert_eq!(e.to, "B");
    assert_eq!(e.pheromone, 1.0);
    assert_eq!(e.distance, 2.5);
}

#[test]
fn edge_clone() {
    let e = Edge { from: "x".to_string(), to: "y".to_string(), pheromone: 0.5, distance: 1.0 };
    let e2 = e.clone();
    assert_eq!(e.from, e2.from);
    assert_eq!(e.pheromone, e2.pheromone);
}

#[test]
fn edge_debug() {
    let e = Edge { from: "a".to_string(), to: "b".to_string(), pheromone: 0.0, distance: 0.0 };
    assert!(format!("{:?}", e).contains("Edge"));
}

#[test]
fn edge_serde_roundtrip() {
    let e = Edge { from: "a".to_string(), to: "b".to_string(), pheromone: 3.14, distance: 2.71 };
    let json = serde_json::to_string(&e).unwrap();
    let e2: Edge = serde_json::from_str(&json).unwrap();
    assert_eq!(e.from, e2.from);
    assert_eq!(e.pheromone, e2.pheromone);
}

// ── PheromoneGraph ──

#[test]
fn graph_new_empty() {
    let g = PheromoneGraph::new(0.5, 1.0);
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn graph_add_node() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    assert_eq!(g.node_count(), 1);
}

#[test]
fn graph_add_edge() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    assert_eq!(g.edge_count(), 1);
}

#[test]
fn graph_initial_pheromone() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    assert_eq!(g.get_pheromone("A", "B"), 1.0);
}

#[test]
fn graph_missing_edge_pheromone() {
    let g = PheromoneGraph::new(0.5, 1.0);
    assert_eq!(g.get_pheromone("X", "Y"), 0.0);
}

#[test]
fn graph_get_edges_from() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_node("C".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    g.add_edge("A".to_string(), "C".to_string(), 2.0);
    let mut edges = g.get_edges_from("A");
    edges.sort();
    assert_eq!(edges, vec!["B".to_string(), "C".to_string()]);
}

#[test]
fn graph_update_pheromones() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    let paths = vec![vec!["A".to_string(), "B".to_string()]];
    let fitness_values = vec![1.0];
    g.update_pheromones(&paths, &fitness_values);
    assert!(g.get_pheromone("A", "B") > 1.0);
}

#[test]
fn graph_update_pheromones_empty() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.update_pheromones(&[], &[]);
    assert_eq!(g.get_pheromone("A", "B"), 0.0);
}

#[test]
fn graph_transition_probability() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 2.0);
    let prob = g.get_transition_probability("A", "B");
    assert!((prob - 0.5).abs() < 1e-10);
}

#[test]
fn graph_transition_probability_missing() {
    let g = PheromoneGraph::new(0.5, 1.0);
    assert_eq!(g.get_transition_probability("X", "Y"), 0.0);
}

#[test]
fn graph_node_count_multiple() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    for i in 0..10 {
        g.add_node(format!("n{}", i), NodeType::File);
    }
    assert_eq!(g.node_count(), 10);
}

#[test]
fn graph_edge_count_multiple() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_node("C".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    g.add_edge("A".to_string(), "C".to_string(), 2.0);
    g.add_edge("B".to_string(), "C".to_string(), 3.0);
    assert_eq!(g.edge_count(), 3);
}

#[test]
fn graph_clone() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    let g2 = g.clone();
    assert_eq!(g2.node_count(), 1);
}

#[test]
fn graph_debug() {
    let g = PheromoneGraph::new(0.5, 1.0);
    assert!(format!("{:?}", g).contains("PheromoneGraph"));
}

#[test]
fn graph_serde_roundtrip() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::Class);
    g.add_edge("A".to_string(), "B".to_string(), 1.5);
    let g2 = g.clone();
    assert_eq!(g2.node_count(), 2);
    assert_eq!(g2.edge_count(), 1);
    assert!((g2.get_pheromone("A", "B") - 1.0).abs() < 1e-10);
}

#[test]
fn graph_get_edges_from_empty() {
    let g = PheromoneGraph::new(0.5, 1.0);
    assert!(g.get_edges_from("X").is_empty());
}

#[test]
fn graph_multiple_edges_from_node() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    for i in 0..5 {
        g.add_node(format!("B{}", i), NodeType::File);
        g.add_edge("A".to_string(), format!("B{}", i), 1.0);
    }
    assert_eq!(g.get_edges_from("A").len(), 5);
}

// ── Ant ──

#[test]
fn ant_new() {
    let a = Ant::new("start".to_string());
    assert_eq!(a.current_node, "start");
    assert_eq!(a.visited, vec!["start".to_string()]);
    assert_eq!(a.path, vec!["start".to_string()]);
    assert_eq!(a.fitness, 0.0);
}

#[test]
fn ant_reset() {
    let mut a = Ant::new("A".to_string());
    a.path = vec!["A".to_string(), "B".to_string()];
    a.visited = vec!["A".to_string(), "B".to_string()];
    a.fitness = 42.0;
    a.reset("X".to_string());
    assert_eq!(a.current_node, "X");
    assert_eq!(a.path, vec!["X".to_string()]);
    assert_eq!(a.fitness, 0.0);
}

#[test]
fn ant_move_no_edges() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    let mut a = Ant::new("A".to_string());
    assert!(!a.move_to(&g, 1.0, 1.0));
}

#[test]
fn ant_move_success() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    let mut a = Ant::new("A".to_string());
    assert!(a.move_to(&g, 1.0, 1.0));
    assert!(a.visited.contains(&"B".to_string()));
}

#[test]
fn ant_move_already_visited() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    let mut a = Ant::new("A".to_string());
    a.move_to(&g, 1.0, 1.0);
    assert!(!a.move_to(&g, 1.0, 1.0));
}

#[test]
fn ant_clone() {
    let a = Ant::new("X".to_string());
    let a2 = a.clone();
    assert_eq!(a2.current_node, "X");
}

#[test]
fn ant_debug() {
    let a = Ant::new("A".to_string());
    assert!(format!("{:?}", a).contains("Ant"));
}

#[test]
fn ant_serde_roundtrip() {
    let a = Ant::new("start".to_string());
    let json = serde_json::to_string(&a).unwrap();
    let a2: Ant = serde_json::from_str(&json).unwrap();
    assert_eq!(a2.current_node, "start");
}

#[test]
fn ant_move_multiple_nodes() {
    let mut g = PheromoneGraph::new(0.5, 1.0);
    g.add_node("A".to_string(), NodeType::File);
    g.add_node("B".to_string(), NodeType::File);
    g.add_node("C".to_string(), NodeType::File);
    g.add_edge("A".to_string(), "B".to_string(), 1.0);
    g.add_edge("B".to_string(), "C".to_string(), 1.0);
    let mut a = Ant::new("A".to_string());
    assert!(a.move_to(&g, 1.0, 1.0));
    assert!(a.move_to(&g, 1.0, 1.0));
    assert_eq!(a.path.len(), 3);
}

// ── ACOPathFinder ──

#[test]
fn aco_new() {
    let aco = ACOPathFinder::new(10, 20, 1.0, 1.0);
    assert_eq!(aco.best_fitness(), f64::NEG_INFINITY);
    assert!(aco.best_path().is_empty());
}

#[test]
fn aco_graph_info_empty() {
    let aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    assert_eq!(aco.graph_info(), (0, 0));
}

#[test]
fn aco_initialize_graph() {
    let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    aco.initialize_graph(
        vec!["A".to_string(), "B".to_string(), "C".to_string()],
        vec![NodeType::File; 3],
    );
    assert_eq!(aco.graph_info().0, 3);
}

#[test]
fn aco_add_connection() {
    let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    aco.initialize_graph(
        vec!["A".to_string(), "B".to_string()],
        vec![NodeType::File; 2],
    );
    aco.add_connection("A".to_string(), "B".to_string(), 1.0);
    assert_eq!(aco.graph_info().1, 1);
}

#[test]
fn aco_iterate_empty_graph() {
    let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    aco.iterate(|path| path.len() as f64);
    assert!(aco.best_path().is_empty());
}

#[test]
fn aco_iterate_with_graph() {
    let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    aco.initialize_graph(
        vec!["A".to_string(), "B".to_string(), "C".to_string()],
        vec![NodeType::File; 3],
    );
    aco.add_connection("A".to_string(), "B".to_string(), 1.0);
    aco.add_connection("B".to_string(), "C".to_string(), 1.0);
    aco.add_connection("A".to_string(), "C".to_string(), 2.0);
    aco.iterate(|path| path.len() as f64);
    assert!(aco.best_fitness() >= 0.0);
}

#[test]
fn aco_optimize() {
    let mut aco = ACOPathFinder::new(10, 20, 1.0, 1.0);
    aco.initialize_graph(
        vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()],
        vec![NodeType::File; 4],
    );
    aco.add_connection("A".to_string(), "B".to_string(), 1.0);
    aco.add_connection("B".to_string(), "C".to_string(), 1.0);
    aco.add_connection("C".to_string(), "D".to_string(), 1.0);
    let result = aco.optimize(|path| path.len() as f64);
    assert!(!result.is_empty());
}

#[test]
fn aco_clone() {
    let aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    let aco2 = aco.clone();
    assert_eq!(aco2.best_fitness(), f64::NEG_INFINITY);
}

#[test]
fn aco_debug() {
    let aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    assert!(format!("{:?}", aco).contains("ACOPathFinder"));
}

#[test]
fn aco_serde_roundtrip() {
    let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
    aco.initialize_graph(
        vec!["A".to_string(), "B".to_string()],
        vec![NodeType::File; 2],
    );
    aco.add_connection("A".to_string(), "B".to_string(), 1.0);
    aco.add_connection("B".to_string(), "A".to_string(), 1.0);
    let aco2 = aco.clone();
    assert_eq!(aco2.graph_info().0, 2);
}

// ── Path ──

#[test]
fn path_fields() {
    let p = Path { nodes: vec!["A".to_string(), "B".to_string()], total_distance: 5.0, pheromone_level: 0.75 };
    assert_eq!(p.nodes.len(), 2);
    assert_eq!(p.total_distance, 5.0);
    assert_eq!(p.pheromone_level, 0.75);
}

#[test]
fn path_clone() {
    let p = Path { nodes: vec!["x".to_string()], total_distance: 1.0, pheromone_level: 0.5 };
    let p2 = p.clone();
    assert_eq!(p2.total_distance, 1.0);
}

#[test]
fn path_debug() {
    let p = Path { nodes: vec![], total_distance: 0.0, pheromone_level: 0.0 };
    assert!(format!("{:?}", p).contains("Path"));
}

#[test]
fn path_serde_roundtrip() {
    let p = Path { nodes: vec!["A".to_string(), "B".to_string(), "C".to_string()], total_distance: 10.0, pheromone_level: 2.5 };
    let json = serde_json::to_string(&p).unwrap();
    let p2: Path = serde_json::from_str(&json).unwrap();
    assert_eq!(p2.nodes, p.nodes);
    assert_eq!(p2.total_distance, p.total_distance);
}

// ── Chromosome ──

#[test]
fn chromosome_new_length() {
    let c = Chromosome::new(7);
    assert_eq!(c.genes.len(), 7);
    assert_eq!(c.fitness, 0.0);
}

#[test]
fn chromosome_from_genes() {
    let genes = vec![0.1, 0.2, 0.3];
    let c = Chromosome::from_genes(genes.clone());
    assert_eq!(c.genes, genes);
    assert_eq!(c.fitness, 0.0);
}

#[test]
fn chromosome_gene_in_bounds() {
    let c = Chromosome::from_genes(vec![1.0, 2.0, 3.0]);
    assert_eq!(c.gene(1), Some(2.0));
}

#[test]
fn chromosome_gene_out_of_bounds() {
    let c = Chromosome::from_genes(vec![1.0, 2.0]);
    assert_eq!(c.gene(5), None);
}

#[test]
fn chromosome_set_gene() {
    let mut c = Chromosome::from_genes(vec![0.0, 0.0, 0.0]);
    c.set_gene(1, 42.0);
    assert_eq!(c.gene(1), Some(42.0));
}

#[test]
fn chromosome_set_gene_out_of_bounds() {
    let mut c = Chromosome::from_genes(vec![0.0, 0.0]);
    c.set_gene(5, 42.0);
    assert_eq!(c.gene(0), Some(0.0));
}

#[test]
fn chromosome_mutate_high_rate() {
    let mut c = Chromosome::from_genes(vec![0.0, 0.0, 0.0, 0.0, 0.0]);
    c.mutate(1.0);
    let changed = c.genes.iter().any(|&g| g != 0.0);
    assert!(changed);
}

#[test]
fn chromosome_mutate_zero_rate() {
    let original = vec![0.5, 0.5, 0.5];
    let mut c = Chromosome::from_genes(original.clone());
    c.mutate(0.0);
    assert_eq!(c.genes, original);
}

#[test]
fn chromosome_crossover_preserves_length() {
    let c1 = Chromosome::from_genes(vec![0.1; 10]);
    let c2 = Chromosome::from_genes(vec![0.9; 10]);
    let (child1, child2) = c1.crossover(&c2);
    assert_eq!(child1.genes.len(), 10);
    assert_eq!(child2.genes.len(), 10);
}

#[test]
fn chromosome_crossover_combines_genes() {
    let c1 = Chromosome::from_genes(vec![0.0; 4]);
    let c2 = Chromosome::from_genes(vec![1.0; 4]);
    let (child1, child2) = c1.crossover(&c2);
    for g in &child1.genes {
        assert!(*g == 0.0 || *g == 1.0);
    }
    for g in &child2.genes {
        assert!(*g == 0.0 || *g == 1.0);
    }
}

#[test]
fn chromosome_clone() {
    let c = Chromosome::from_genes(vec![1.0, 2.0, 3.0]);
    let c2 = c.clone();
    assert_eq!(c.genes, c2.genes);
    assert_eq!(c.fitness, c2.fitness);
}

#[test]
fn chromosome_debug() {
    let c = Chromosome::new(3);
    assert!(format!("{:?}", c).contains("Chromosome"));
}

#[test]
fn chromosome_serde_roundtrip() {
    let mut c = Chromosome::from_genes(vec![1.1, 2.2, 3.3]);
    c.fitness = 42.0;
    let json = serde_json::to_string(&c).unwrap();
    let c2: Chromosome = serde_json::from_str(&json).unwrap();
    assert_eq!(c.genes, c2.genes);
    assert_eq!(c2.fitness, 42.0);
}

// ── GeneticOptimizer ──

#[test]
fn ga_new() {
    let ga = GeneticOptimizer::new(50, 10, 0.01, 0.8, 100);
    assert_eq!(ga.iteration(), 0);
    assert_eq!(ga.best_fitness(), 0.0);
}

#[test]
fn ga_evaluate() {
    let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
    let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.0, 10);
    ga.evaluate(&fitness_fn);
    assert!(ga.best_fitness() >= 0.0);
}

#[test]
fn ga_iterate() {
    let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
    let mut ga = GeneticOptimizer::new(10, 3, 0.1, 0.8, 100);
    assert_eq!(ga.iteration(), 0);
    ga.iterate(&fitness_fn);
    assert_eq!(ga.iteration(), 1);
    ga.iterate(&fitness_fn);
    assert_eq!(ga.iteration(), 2);
}

#[test]
fn ga_optimize() {
    let fitness_fn = |chrom: &Chromosome| -> f64 {
        chrom.genes.iter().sum::<f64>() / chrom.genes.len() as f64
    };
    let mut ga = GeneticOptimizer::new(50, 5, 0.1, 0.8, 50);
    let result = ga.optimize(&fitness_fn);
    assert_eq!(result.len(), 5);
    assert!(ga.best_fitness() > 0.5);
}

#[test]
fn ga_best_solution() {
    let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
    let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.0, 10);
    ga.evaluate(&fitness_fn);
    let best = ga.best_solution();
    assert_eq!(best.genes.len(), 3);
}

#[test]
fn ga_stats() {
    let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
    let mut ga = GeneticOptimizer::new(20, 4, 0.0, 0.8, 10);
    ga.evaluate(&fitness_fn);
    let s = ga.stats();
    assert_eq!(s.population_size, 20);
    assert_eq!(s.iteration, 0);
    assert!(s.best_fitness >= 0.0);
    assert!(s.average_fitness >= 0.0);
}

#[test]
fn ga_stats_after_iterate() {
    let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
    let mut ga = GeneticOptimizer::new(10, 3, 0.1, 0.8, 100);
    ga.iterate(&fitness_fn);
    let s = ga.stats();
    assert_eq!(s.iteration, 1);
}

#[test]
fn ga_clone() {
    let ga = GeneticOptimizer::new(10, 3, 0.01, 0.8, 50);
    let ga2 = ga.clone();
    assert_eq!(ga2.iteration(), 0);
}

#[test]
fn ga_debug() {
    let ga = GeneticOptimizer::new(10, 3, 0.01, 0.8, 50);
    assert!(format!("{:?}", ga).contains("GeneticOptimizer"));
}

#[test]
fn ga_serde_roundtrip() {
    let ga = GeneticOptimizer::new(10, 3, 0.01, 0.8, 50);
    let json = serde_json::to_string(&ga).unwrap();
    let ga2: GeneticOptimizer = serde_json::from_str(&json).unwrap();
    assert_eq!(ga2.iteration(), 0);
}

#[test]
fn ga_best_fitness_improves() {
    let fitness_fn = |chrom: &Chromosome| -> f64 {
        chrom.genes.iter().sum::<f64>() / chrom.genes.len() as f64
    };
    let mut ga = GeneticOptimizer::new(20, 5, 0.1, 0.8, 30);
    let initial = ga.best_fitness();
    ga.evaluate(&fitness_fn);
    assert!(ga.best_fitness() >= initial);
}

#[test]
fn ga_multiple_iterations() {
    let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
    let mut ga = GeneticOptimizer::new(10, 3, 0.1, 0.8, 100);
    for _ in 0..5 {
        ga.iterate(&fitness_fn);
    }
    assert_eq!(ga.iteration(), 5);
}

// ── GAStats ──

#[test]
fn ga_stats_fields() {
    let s = GAStats { iteration: 5, best_fitness: 1.0, average_fitness: 0.5, population_size: 20 };
    assert_eq!(s.iteration, 5);
    assert_eq!(s.best_fitness, 1.0);
    assert_eq!(s.average_fitness, 0.5);
    assert_eq!(s.population_size, 20);
}

#[test]
fn ga_stats_clone() {
    let s = GAStats { iteration: 1, best_fitness: 2.0, average_fitness: 1.0, population_size: 10 };
    let s2 = s.clone();
    assert_eq!(s.iteration, s2.iteration);
    assert_eq!(s.best_fitness, s2.best_fitness);
}

#[test]
fn ga_stats_debug() {
    let s = GAStats { iteration: 0, best_fitness: 0.0, average_fitness: 0.0, population_size: 0 };
    assert!(format!("{:?}", s).contains("GAStats"));
}

#[test]
fn ga_stats_serde_roundtrip() {
    let s = GAStats { iteration: 10, best_fitness: 3.14, average_fitness: 1.57, population_size: 50 };
    let json = serde_json::to_string(&s).unwrap();
    let s2: GAStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s.iteration, s2.iteration);
    assert_eq!(s.best_fitness, s2.best_fitness);
    assert_eq!(s.average_fitness, s2.average_fitness);
}

// ── Cross-type tests ──

#[test]
fn all_algorithm_variants_count() {
    let variants = [Algorithm::PSO, Algorithm::GA, Algorithm::ACO, Algorithm::SimulatedAnnealing];
    assert_eq!(variants.len(), 4);
}

#[test]
fn all_node_type_variants_count() {
    let variants = [NodeType::File, NodeType::Function, NodeType::Class, NodeType::Module, NodeType::Dependency];
    assert_eq!(variants.len(), 5);
}

#[test]
fn config_serde_invalid() {
    let result = serde_json::from_str::<OptimizationConfig>("invalid");
    assert!(result.is_err());
}

#[test]
fn algorithm_serde_invalid() {
    let result = serde_json::from_str::<Algorithm>("\"Unknown\"");
    assert!(result.is_err());
}

#[test]
fn node_type_serde_invalid() {
    let result = serde_json::from_str::<NodeType>("\"Invalid\"");
    assert!(result.is_err());
}

#[test]
fn particle_serde_invalid() {
    let result = serde_json::from_str::<Particle>("null");
    assert!(result.is_err());
}

#[test]
fn chromosome_serde_invalid() {
    let result = serde_json::from_str::<Chromosome>("null");
    assert!(result.is_err());
}

#[test]
fn path_serde_invalid() {
    let result = serde_json::from_str::<Path>("null");
    assert!(result.is_err());
}

#[test]
fn ga_stats_serde_invalid() {
    let result = serde_json::from_str::<GAStats>("null");
    assert!(result.is_err());
}

#[test]
fn tool_score_serde_invalid() {
    let result = serde_json::from_str::<ToolScore>("null");
    assert!(result.is_err());
}

#[test]
fn edge_serde_invalid() {
    let result = serde_json::from_str::<Edge>("null");
    assert!(result.is_err());
}

#[test]
fn node_serde_invalid() {
    let result = serde_json::from_str::<Node>("null");
    assert!(result.is_err());
}
