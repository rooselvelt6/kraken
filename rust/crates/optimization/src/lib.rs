pub mod aco;
pub mod ga;
pub mod pso;
pub mod sa;

pub use aco::{ACOPathFinder, Node, NodeType, Path, PheromoneGraph};
pub use ga::{Chromosome, FitnessFn, GeneticOptimizer};
pub use pso::{PSOToolSelector, Particle, ToolScore};
pub use sa::SimulatedAnnealer;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationConfig {
    pub population_size: usize,
    pub max_iterations: usize,
    pub convergence_threshold: f64,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            population_size: 30,
            max_iterations: 100,
            convergence_threshold: 1e-6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    PSO,
    GA,
    ACO,
    SimulatedAnnealing,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::PSO
    }
}
