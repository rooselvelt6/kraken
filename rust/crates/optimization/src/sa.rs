//! Simulated Annealing (SA) Implementation
//!
//! Simulated annealing is a metaheuristic used to approximate global optimum
//! in large search spaces. It inspired by the process of annealing in metallurgy.
//!
//! **Application in Claw Code**: Escape from local optima during refactoring decisions.

use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedAnnealer {
    current_solution: Vec<f64>,
    best_solution: Vec<f64>,
    current_energy: f64,
    best_energy: f64,
    temperature: f64,
    cooling_rate: f64,
    min_temperature: f64,
    iterations_per_temp: usize,
}

impl SimulatedAnnealer {
    pub fn new(
        dimensions: usize,
        initial_temperature: f64,
        cooling_rate: f64,
        min_temperature: f64,
        iterations_per_temp: usize,
    ) -> Self {
        let mut rng = rand::thread_rng();

        let current_solution: Vec<f64> = (0..dimensions).map(|_| rng.gen()).collect();
        let current_energy = f64::INFINITY;

        Self {
            current_solution: current_solution.clone(),
            best_solution: current_solution,
            current_energy,
            best_energy: f64::INFINITY,
            temperature: initial_temperature,
            cooling_rate,
            min_temperature,
            iterations_per_temp,
        }
    }

    pub fn with_default_params(dimensions: usize) -> Self {
        Self::new(dimensions, 1000.0, 0.995, 0.001, 100)
    }

    pub fn set_initial_solution(&mut self, solution: Vec<f64>) {
        self.current_solution = solution.clone();
        self.best_solution = solution;
    }

    pub fn run_iteration<F>(&mut self, energy_fn: F)
    where
        F: Fn(&[f64]) -> f64 + Copy,
    {
        let mut rng = rand::thread_rng();

        // Evaluate current solution
        self.current_energy = energy_fn(&self.current_solution);

        // Track best
        if self.current_energy < self.best_energy {
            self.best_energy = self.current_energy;
            self.best_solution = self.current_solution.clone();
        }

        // Generate neighbor
        let mut neighbor = self.current_solution.clone();
        let idx = rng.gen_range(0..neighbor.len());
        neighbor[idx] += rng.gen_range(-0.1..0.1);
        neighbor[idx] = neighbor[idx].clamp(0.0, 1.0);

        // Calculate delta
        let neighbor_energy = energy_fn(&neighbor);
        let delta = neighbor_energy - self.current_energy;

        // Acceptance criterion
        let accept = if delta < 0.0 {
            true
        } else {
            let probability = (-delta / self.temperature).exp();
            rng.gen::<f64>() < probability
        };

        if accept {
            self.current_solution = neighbor;
            self.current_energy = neighbor_energy;
        }

        // Cool down
        self.temperature *= self.cooling_rate;
    }

    pub fn optimize<F>(&mut self, energy_fn: F) -> Vec<f64>
    where
        F: Fn(&[f64]) -> f64 + Copy,
    {
        while self.temperature > self.min_temperature {
            for _ in 0..self.iterations_per_temp {
                self.run_iteration(energy_fn);
            }
        }
        self.best_solution.clone()
    }

    pub fn get_best(&self) -> Vec<f64> {
        self.best_solution.clone()
    }

    pub fn get_best_energy(&self) -> f64 {
        self.best_energy
    }

    pub fn get_temperature(&self) -> f64 {
        self.temperature
    }

    pub fn has_converged(&self) -> bool {
        self.temperature <= self.min_temperature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sa_creation() {
        let sa = SimulatedAnnealer::with_default_params(5);
        assert_eq!(sa.current_solution.len(), 5);
        assert!(sa.temperature > 0.0);
    }

    #[test]
    fn test_sa_optimization() {
        let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| (x - 0.5).powi(2)).sum() };

        let mut sa = SimulatedAnnealer::new(3, 100.0, 0.99, 0.01, 10);
        let result = sa.optimize(energy_fn);

        assert_eq!(result.len(), 3);
    }
}
