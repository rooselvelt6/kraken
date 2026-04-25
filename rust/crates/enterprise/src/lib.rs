//! Enterprise Features for Claw Code Venezuela
//! 
//! This crate provides production-ready features:
//! - Retry logic with exponential backoff
//! - Circuit breaker pattern
//! - Health checks
//! - Graceful degradation
//! - Metrics collection
//! - Structured logging
//! - Distributed tracing

pub mod retry;
pub mod circuit_breaker;
pub mod health;
pub mod metrics;
pub mod graceful_degradation;
pub mod logging;
pub mod tracing;

pub use retry::{RetryConfig, RetryStrategy};
pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use health::{HealthCheck, HealthStatus, ProviderHealth};
pub use metrics::{MetricsCollector, ProviderMetrics};
pub use graceful_degradation::GracefulDegradation;
pub use logging::{JsonLogger, LogEntry, Level};
pub use tracing::{TraceContext, SpanTracer, TraceCollector};

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert!(config.initial_delay_ms > 0);
    }
    
    #[test]
    fn test_circuit_breaker_initial_state() {
        let cb = CircuitBreaker::new(5, std::time::Duration::from_secs(30));
        assert!(matches!(cb.state(), CircuitState::Closed));
    }
    
    #[test]
    fn test_health_status() {
        let health = ProviderHealth::new("deepseek".to_string());
        assert!(matches!(health.status, HealthStatus::Unknown));
    }
}