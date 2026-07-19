#![allow(
    clippy::all,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::must_use_candidate,
    clippy::uninlined_format_args,
    clippy::implicit_clone,
    clippy::assigning_clones,
    clippy::map_unwrap_or,
    clippy::unnecessary_mut_passed
)]

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimization_config_default() {
        let config = OptimizationConfig::default();
        assert_eq!(config.population_size, 30);
        assert_eq!(config.max_iterations, 100);
        assert_eq!(config.convergence_threshold, 1e-6);
    }

    #[test]
    fn test_optimization_config_custom() {
        let config = OptimizationConfig {
            population_size: 50,
            max_iterations: 200,
            convergence_threshold: 1e-8,
        };
        assert_eq!(config.population_size, 50);
        assert_eq!(config.max_iterations, 200);
        assert_eq!(config.convergence_threshold, 1e-8);
    }

    #[test]
    fn test_algorithm_default() {
        assert!(matches!(Algorithm::default(), Algorithm::PSO));
    }

    #[test]
    fn test_algorithm_variants() {
        assert!(matches!(Algorithm::PSO, Algorithm::PSO));
        assert!(matches!(Algorithm::GA, Algorithm::GA));
        assert!(matches!(Algorithm::ACO, Algorithm::ACO));
        assert!(matches!(Algorithm::SimulatedAnnealing, Algorithm::SimulatedAnnealing));
    }

    #[test]
    fn test_algorithm_equality() {
        assert_eq!(Algorithm::PSO, Algorithm::PSO);
        assert_ne!(Algorithm::PSO, Algorithm::GA);
        assert_ne!(Algorithm::ACO, Algorithm::SimulatedAnnealing);
    }

    #[test]
    fn test_optimization_config_clone() {
        let config = OptimizationConfig {
            population_size: 10,
            max_iterations: 50,
            convergence_threshold: 0.1,
        };
        let cloned = config.clone();
        assert_eq!(config.population_size, cloned.population_size);
        assert_eq!(config.max_iterations, cloned.max_iterations);
        assert_eq!(config.convergence_threshold, cloned.convergence_threshold);
    }
}
