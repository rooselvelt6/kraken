/// Health checks for providers
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub name: String,
    pub status: HealthStatus,
    pub latency_ms: u64,
    pub last_check: DateTime<Utc>,
    pub error_rate: f64,
    pub total_requests: u64,
    pub failed_requests: u64,
}

impl ProviderHealth {
    pub fn new(name: String) -> Self {
        Self {
            name,
            status: HealthStatus::Unknown,
            latency_ms: 0,
            last_check: Utc::now(),
            error_rate: 0.0,
            total_requests: 0,
            failed_requests: 0,
        }
    }

    pub fn record_success(&mut self, latency_ms: u64) {
        self.latency_ms = latency_ms;
        self.last_check = Utc::now();
        self.total_requests += 1;

        self.update_status();
    }

    pub fn record_failure(&mut self) {
        self.last_check = Utc::now();
        self.total_requests += 1;
        self.failed_requests += 1;

        self.error_rate = self.failed_requests as f64 / self.total_requests as f64;
        self.update_status();
    }

    fn update_status(&mut self) {
        if self.total_requests > 10 && self.error_rate > 0.5 {
            self.status = HealthStatus::Unhealthy;
        } else if self.total_requests > 10 && self.error_rate > 0.1 {
            self.status = HealthStatus::Degraded;
        } else {
            self.status = HealthStatus::Healthy;
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(
            self.status,
            HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthCheck {
    pub providers: std::collections::HashMap<String, ProviderHealthStatus>,
    pub status: HealthStatus,
    pub uptime_seconds: u64,
    pub requests_total: u64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealthStatus {
    pub status: String,
    pub latency_ms: u64,
    pub error_rate: f64,
}

impl HealthCheck {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_provider(&mut self, health: ProviderHealth) {
        let status_str = match health.status {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
            HealthStatus::Unknown => "unknown",
        };

        self.providers.insert(
            health.name,
            ProviderHealthStatus {
                status: status_str.to_string(),
                latency_ms: health.latency_ms,
                error_rate: health.error_rate,
            },
        );
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_health_recording() {
        let mut health = ProviderHealth::new("deepseek".to_string());

        health.record_success(100);
        assert!(matches!(health.status, HealthStatus::Healthy));

        health.record_failure();
        assert!(health.is_available());

        for _ in 0..20 {
            health.record_failure();
        }

        assert!(matches!(health.status, HealthStatus::Unhealthy));
    }

    #[test]
    fn test_health_check_json() {
        let mut check = HealthCheck::new();
        check.add_provider(ProviderHealth::new("deepseek".to_string()));

        let json = check.to_json();
        assert!(json.contains("deepseek"));
    }
}
