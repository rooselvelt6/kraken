/// Circuit Breaker implementation

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self::Closed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub recovery_timeout_ms: u64,
    pub half_open_requests: u32,

    #[serde(skip)]
    state: CircuitState,
    failures: u32,
    successes: u32,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            success_threshold: 2,
            recovery_timeout_ms: recovery_timeout.as_millis() as u64,
            half_open_requests: 2,
            state: CircuitState::Closed,
            failures: 0,
            successes: 0,
        }
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }

    pub fn can_execute(&self) -> bool {
        !matches!(self.state, CircuitState::Open)
    }

    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.successes += 1;
                if self.successes >= self.success_threshold {
                    self.state = CircuitState::Closed;
                    self.failures = 0;
                    self.successes = 0;
                }
            }
            CircuitState::Closed => {
                self.failures = 0;
            }
            CircuitState::Open => {}
        }
    }

    pub fn record_failure(&mut self) {
        self.failures += 1;

        match self.state {
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.successes = 0;
            }
            CircuitState::Closed => {
                if self.failures >= self.failure_threshold {
                    self.state = CircuitState::Open;
                }
            }
            CircuitState::Open => {}
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.state, CircuitState::Closed)
    }

    pub fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.failures = 0;
        self.successes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed_by_default() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        assert!(matches!(cb.state(), CircuitState::Closed));
        assert!(cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let mut cb = CircuitBreaker::new(3, Duration::from_secs(30));

        for _ in 0..3 {
            cb.record_failure();
        }

        assert!(matches!(cb.state(), CircuitState::Open));
        assert!(!cb.can_execute());
    }
}
