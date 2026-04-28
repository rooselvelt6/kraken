//! Metrics collection for providers

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderMetrics {
    pub provider: String,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub tokens_used: u64,
    pub cost_usd: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsCollector {
    providers: HashMap<String, ProviderMetrics>,
    latencies: HashMap<String, Vec<u64>>,
    total_requests: u64,
    total_errors: u64,
    start_time: DateTime<Utc>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            latencies: HashMap::new(),
            total_requests: 0,
            total_errors: 0,
            start_time: Utc::now(),
        }
    }

    pub fn record_request(&mut self, provider: &str, latency_ms: u64, tokens: u64) {
        self.total_requests += 1;

        let metrics = self
            .providers
            .entry(provider.to_string())
            .or_insert_with(|| ProviderMetrics {
                provider: provider.to_string(),
                ..Default::default()
            });

        metrics.total_requests += 1;
        metrics.successful_requests += 1;
        metrics.tokens_used += tokens;
        metrics.avg_latency_ms = (metrics.avg_latency_ms * (metrics.total_requests - 1) as f64
            + latency_ms as f64)
            / metrics.total_requests as f64;

        self.latencies
            .entry(provider.to_string())
            .or_insert_with(Vec::new)
            .push(latency_ms);

        self.update_percentiles(provider);
    }

    pub fn record_error(&mut self, provider: &str) {
        self.total_errors += 1;
        self.total_requests += 1;

        let metrics = self
            .providers
            .entry(provider.to_string())
            .or_insert_with(|| ProviderMetrics {
                provider: provider.to_string(),
                ..Default::default()
            });

        metrics.total_requests += 1;
        metrics.failed_requests += 1;
    }

    fn update_percentiles(&mut self, provider: &str) {
        if let Some(latencies) = self.latencies.get(provider) {
            if let Some(metrics) = self.providers.get_mut(provider) {
                let mut sorted = latencies.clone();
                sorted.sort();

                let len = sorted.len();
                if len > 0 {
                    metrics.p50_latency_ms = sorted[len / 2];
                    metrics.p95_latency_ms =
                        sorted[(len as f64 * 0.95) as usize].min(sorted[len - 1]);
                    metrics.p99_latency_ms =
                        sorted[(len as f64 * 0.99) as usize].min(sorted[len - 1]);
                }
            }
        }
    }

    pub fn report(&self, provider: &str) -> Option<ProviderMetrics> {
        self.providers.get(provider).cloned()
    }

    pub fn all_reports(&self) -> HashMap<String, ProviderMetrics> {
        self.providers.clone()
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.total_errors as f64 / self.total_requests as f64
    }

    pub fn uptime_seconds(&self) -> u64 {
        (Utc::now() - self.start_time).num_seconds() as u64
    }
}

pub struct MetricsCollectorSync {
    inner: Arc<Mutex<MetricsCollector>>,
}

impl MetricsCollectorSync {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MetricsCollector::new())),
        }
    }

    pub fn record_request(&self, provider: &str, latency_ms: u64, tokens: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.record_request(provider, latency_ms, tokens);
        }
    }

    pub fn record_error(&self, provider: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.record_error(provider);
        }
    }

    pub fn report(&self, provider: &str) -> Option<ProviderMetrics> {
        self.inner.lock().ok()?.report(provider)
    }

    pub fn error_rate(&self) -> f64 {
        self.inner
            .lock()
            .ok()
            .map(|i| i.error_rate())
            .unwrap_or(0.0)
    }
}

impl Default for MetricsCollectorSync {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let mut collector = MetricsCollector::new();

        collector.record_request("deepseek", 100, 1000);
        collector.record_request("deepseek", 200, 1500);
        collector.record_error("deepseek");

        let report = collector.report("deepseek").unwrap();

        assert_eq!(report.total_requests, 3);
        assert_eq!(report.successful_requests, 2);
        assert_eq!(report.failed_requests, 1);
    }

    #[test]
    fn test_error_rate() {
        let mut collector = MetricsCollector::new();

        collector.record_error("deepseek");
        collector.record_error("deepseek");
        collector.record_request("deepseek", 100, 1000);

        let error_rate = collector.error_rate();
        assert!(error_rate > 0.66 && error_rate < 0.67);
    }
}
