#![allow(clippy::all, clippy::map_unwrap_or)]
/// Enterprise Features for Claw Code Venezuela
///
/// This crate provides production-ready features:
/// - Retry logic with exponential backoff
/// - Circuit breaker pattern
/// - Health checks
/// - Graceful degradation
/// - Metrics collection
/// - Structured logging
/// - Distributed tracing
/// - Performance optimizations
/// - Enterprise audit and rate limiting
pub mod circuit_breaker;
pub mod enterprise_features;
pub mod graceful_degradation;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod performance;
pub mod retry;
pub mod tracing;

pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use enterprise_features::{
    AuditAction, AuditResult, EnterpriseAuditEntry, EnterpriseAuditLog, EnterpriseConfig,
    RateLimitBucket, RateLimiter,
};
pub use graceful_degradation::GracefulDegradation;
pub use health::{HealthCheck, HealthStatus, ProviderHealth};
pub use logging::{JsonLogger, Level, LogEntry};
pub use metrics::{MetricsCollector, ProviderMetrics};
pub use performance::{ConnectionPool, TimedCache};
pub use retry::{RetryConfig, RetryStrategy};
pub use tracing::{SpanTracer, TraceCollector, TraceContext};

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
