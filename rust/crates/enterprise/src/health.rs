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

    #[test]
    fn test_health_status_default() {
        assert!(matches!(HealthStatus::default(), HealthStatus::Unknown));
    }

    #[test]
    fn test_health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
        assert_ne!(HealthStatus::Degraded, HealthStatus::Unknown);
    }

    #[test]
    fn test_health_status_serialization() {
        let statuses = [
            HealthStatus::Unknown,
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: HealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, deserialized);
        }
    }

    #[test]
    fn test_provider_health_new() {
        let health = ProviderHealth::new("test_provider".to_string());
        assert_eq!(health.name, "test_provider");
        assert!(matches!(health.status, HealthStatus::Unknown));
        assert_eq!(health.latency_ms, 0);
        assert_eq!(health.error_rate, 0.0);
        assert_eq!(health.total_requests, 0);
        assert_eq!(health.failed_requests, 0);
    }

    #[test]
    fn test_provider_health_record_success() {
        let mut health = ProviderHealth::new("p1".to_string());
        health.record_success(150);
        assert_eq!(health.latency_ms, 150);
        assert_eq!(health.total_requests, 1);
        assert_eq!(health.failed_requests, 0);
        assert!(matches!(health.status, HealthStatus::Healthy));
    }

    #[test]
    fn test_provider_health_record_failure() {
        let mut health = ProviderHealth::new("p1".to_string());
        health.record_failure();
        assert_eq!(health.total_requests, 1);
        assert_eq!(health.failed_requests, 1);
        assert_eq!(health.error_rate, 1.0);
    }

    #[test]
    fn test_provider_health_degraded_status() {
        let mut health = ProviderHealth::new("p1".to_string());
        // Need > 10 total requests and error rate > 0.1
        for _ in 0..10 {
            health.record_success(10);
        }
        // Now record 2 failures out of 12 total -> rate ~0.167
        health.record_failure();
        health.record_failure();
        assert!(matches!(health.status, HealthStatus::Degraded));
        assert!(health.is_available());
    }

    #[test]
    fn test_provider_health_unhealthy_status() {
        let mut health = ProviderHealth::new("p1".to_string());
        // Need > 10 total requests and error rate > 0.5
        for _ in 0..5 {
            health.record_success(10);
        }
        for _ in 0..10 {
            health.record_failure();
        }
        // 15 total, 10 failed -> rate 0.667
        assert!(matches!(health.status, HealthStatus::Unhealthy));
        assert!(!health.is_available());
    }

    #[test]
    fn test_provider_health_is_available() {
        let mut health = ProviderHealth::new("p1".to_string());
        assert!(health.is_available()); // Unknown is available

        health.record_success(10);
        assert!(health.is_available()); // Healthy

        // Make degraded
        for _ in 0..10 {
            health.record_success(10);
        }
        health.record_failure();
        health.record_failure();
        assert!(health.is_available()); // Degraded is available

        // Make unhealthy
        for _ in 0..15 {
            health.record_failure();
        }
        assert!(!health.is_available()); // Unhealthy is not available
    }

    #[test]
    fn test_provider_health_multiple_successes() {
        let mut health = ProviderHealth::new("p1".to_string());
        health.record_success(100);
        health.record_success(200);
        health.record_success(50);
        assert_eq!(health.total_requests, 3);
        assert_eq!(health.latency_ms, 50);
        assert_eq!(health.failed_requests, 0);
    }

    #[test]
    fn test_health_check_new() {
        let check = HealthCheck::new();
        assert!(check.providers.is_empty());
        assert!(matches!(check.status, HealthStatus::Unknown));
        assert_eq!(check.uptime_seconds, 0);
        assert_eq!(check.requests_total, 0);
        assert_eq!(check.error_rate, 0.0);
    }

    #[test]
    fn test_health_check_add_provider() {
        let mut check = HealthCheck::new();
        let mut health = ProviderHealth::new("deepseek".to_string());
        health.record_success(100);
        check.add_provider(health);

        assert_eq!(check.providers.len(), 1);
        let p = check.providers.get("deepseek").unwrap();
        assert_eq!(p.status, "healthy");
        assert_eq!(p.latency_ms, 100);
    }

    #[test]
    fn test_health_check_add_provider_statuses() {
        let mut check = HealthCheck::new();

        let mut healthy = ProviderHealth::new("h1".to_string());
        healthy.record_success(10);
        check.add_provider(healthy);

        let mut unhealthy = ProviderHealth::new("u1".to_string());
        for _ in 0..20 {
            unhealthy.record_failure();
        }
        check.add_provider(unhealthy);

        assert_eq!(check.providers.get("h1").unwrap().status, "healthy");
        assert_eq!(check.providers.get("u1").unwrap().status, "unhealthy");
    }

    #[test]
    fn test_health_check_serialization() {
        let mut check = HealthCheck::new();
        let mut health = ProviderHealth::new("p1".to_string());
        health.record_success(200);
        check.add_provider(health);
        check.status = HealthStatus::Healthy;
        check.uptime_seconds = 3600;

        let json = serde_json::to_string(&check).unwrap();
        let deserialized: HealthCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.uptime_seconds, 3600);
        assert!(deserialized.providers.contains_key("p1"));
    }

    #[test]
    fn test_provider_health_serialization() {
        let mut health = ProviderHealth::new("test".to_string());
        health.record_success(150);
        health.record_failure();

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: ProviderHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
        assert_eq!(deserialized.total_requests, 2);
        assert_eq!(deserialized.failed_requests, 1);
    }

    #[test]
    fn test_health_check_to_json_contains_fields() {
        let mut check = HealthCheck::new();
        let health = ProviderHealth::new("deepseek".to_string());
        check.add_provider(health);

        let json = check.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed["providers"].is_object());
    }

    #[test]
    fn test_provider_health_clone() {
        let mut health = ProviderHealth::new("clone_test".to_string());
        health.record_success(500);
        let cloned = health.clone();
        assert_eq!(cloned.name, "clone_test");
        assert_eq!(cloned.latency_ms, 500);
        assert_eq!(cloned.total_requests, 1);
    }

    #[test]
    fn test_provider_health_status_transitions() {
        let mut health = ProviderHealth::new("p".to_string());
        assert!(matches!(health.status, HealthStatus::Unknown));

        health.record_success(10);
        assert!(matches!(health.status, HealthStatus::Healthy));

        // Low error rate, few requests -> stays healthy
        health.record_failure();
        assert!(matches!(health.status, HealthStatus::Healthy));
    }
}
