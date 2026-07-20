/// Metrics collection for providers
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
    use std::thread;

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

    #[test]
    fn test_metrics_collector_new() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.total_requests, 0);
        assert_eq!(collector.total_errors, 0);
        assert!(collector.providers.is_empty());
    }

    #[test]
    fn test_record_request_creates_provider() {
        let mut collector = MetricsCollector::new();
        collector.record_request("new_provider", 50, 500);

        let report = collector.report("new_provider").unwrap();
        assert_eq!(report.provider, "new_provider");
        assert_eq!(report.total_requests, 1);
        assert_eq!(report.successful_requests, 1);
        assert_eq!(report.tokens_used, 500);
    }

    #[test]
    fn test_record_request_avg_latency() {
        let mut collector = MetricsCollector::new();
        collector.record_request("p1", 100, 0);
        collector.record_request("p1", 200, 0);
        collector.record_request("p1", 300, 0);

        let report = collector.report("p1").unwrap();
        assert!((report.avg_latency_ms - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_record_request_percentiles() {
        let mut collector = MetricsCollector::new();
        for i in 1..=100 {
            collector.record_request("p1", i, 0);
        }

        let report = collector.report("p1").unwrap();
        assert!(report.p50_latency_ms > 0);
        assert!(report.p95_latency_ms >= report.p50_latency_ms);
        assert!(report.p99_latency_ms >= report.p95_latency_ms);
    }

    #[test]
    fn test_record_error_increments_totals() {
        let mut collector = MetricsCollector::new();
        collector.record_error("p1");
        collector.record_error("p1");

        assert_eq!(collector.total_errors, 2);
        assert_eq!(collector.total_requests, 2);

        let report = collector.report("p1").unwrap();
        assert_eq!(report.failed_requests, 2);
        assert_eq!(report.total_requests, 2);
    }

    #[test]
    fn test_report_nonexistent_provider() {
        let collector = MetricsCollector::new();
        assert!(collector.report("nonexistent").is_none());
    }

    #[test]
    fn test_all_reports() {
        let mut collector = MetricsCollector::new();
        collector.record_request("p1", 10, 100);
        collector.record_request("p2", 20, 200);

        let reports = collector.all_reports();
        assert_eq!(reports.len(), 2);
        assert!(reports.contains_key("p1"));
        assert!(reports.contains_key("p2"));
    }

    #[test]
    fn test_error_rate_no_requests() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.error_rate(), 0.0);
    }

    #[test]
    fn test_error_rate_all_errors() {
        let mut collector = MetricsCollector::new();
        collector.record_error("p1");
        collector.record_error("p1");
        assert_eq!(collector.error_rate(), 1.0);
    }

    #[test]
    fn test_error_rate_no_errors() {
        let mut collector = MetricsCollector::new();
        collector.record_request("p1", 100, 1000);
        assert_eq!(collector.error_rate(), 0.0);
    }

    #[test]
    fn test_uptime_seconds() {
        let collector = MetricsCollector::new();
        let uptime = collector.uptime_seconds();
        assert!(uptime <= 1);
    }

    #[test]
    fn test_tokens_accumulate() {
        let mut collector = MetricsCollector::new();
        collector.record_request("p1", 10, 100);
        collector.record_request("p1", 10, 200);
        collector.record_request("p1", 10, 300);

        let report = collector.report("p1").unwrap();
        assert_eq!(report.tokens_used, 600);
    }

    #[test]
    fn test_multiple_providers() {
        let mut collector = MetricsCollector::new();
        collector.record_request("deepseek", 100, 500);
        collector.record_request("ollama", 200, 0);
        collector.record_error("bigpickle");

        assert_eq!(collector.all_reports().len(), 3);
        assert_eq!(collector.report("deepseek").unwrap().total_requests, 1);
        assert_eq!(collector.report("ollama").unwrap().total_requests, 1);
        assert_eq!(collector.report("bigpickle").unwrap().failed_requests, 1);
    }

    #[test]
    fn test_provider_metrics_default() {
        let m = ProviderMetrics::default();
        assert_eq!(m.provider, "");
        assert_eq!(m.total_requests, 0);
        assert_eq!(m.cost_usd, 0.0);
    }

    #[test]
    fn test_provider_metrics_serialization() {
        let mut m = ProviderMetrics::default();
        m.provider = "test".to_string();
        m.total_requests = 100;
        m.cost_usd = 0.50;

        let json = serde_json::to_string(&m).unwrap();
        let deserialized: ProviderMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider, "test");
        assert_eq!(deserialized.total_requests, 100);
        assert_eq!(deserialized.cost_usd, 0.50);
    }

    #[test]
    fn test_metrics_collector_sync_new() {
        let collector = MetricsCollectorSync::new();
        assert!(collector.report("nonexistent").is_none());
    }

    #[test]
    fn test_metrics_collector_sync_default() {
        let collector = MetricsCollectorSync::default();
        assert!(collector.report("nonexistent").is_none());
    }

    #[test]
    fn test_metrics_collector_sync_record_request() {
        let collector = MetricsCollectorSync::new();
        collector.record_request("p1", 100, 1000);

        let report = collector.report("p1").unwrap();
        assert_eq!(report.total_requests, 1);
        assert_eq!(report.tokens_used, 1000);
    }

    #[test]
    fn test_metrics_collector_sync_record_error() {
        let collector = MetricsCollectorSync::new();
        collector.record_error("p1");
        collector.record_error("p1");

        let report = collector.report("p1").unwrap();
        assert_eq!(report.failed_requests, 2);
    }

    #[test]
    fn test_metrics_collector_sync_error_rate() {
        let collector = MetricsCollectorSync::new();
        collector.record_error("p1");
        collector.record_request("p1", 100, 0);

        let rate = collector.error_rate();
        assert!((rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_metrics_collector_sync_error_rate_empty() {
        let collector = MetricsCollectorSync::new();
        assert_eq!(collector.error_rate(), 0.0);
    }

    #[test]
    fn test_metrics_collector_sync_concurrent() {
        let collector = Arc::new(MetricsCollectorSync::new());
        let mut handles = vec![];

        for i in 0..10 {
            let collector = collector.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    collector.record_request(&format!("p{}", i), 10, 1);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let report = collector.report("p0").unwrap();
        assert_eq!(report.total_requests, 100);
    }

    #[test]
    fn test_metrics_collector_serialization() {
        let mut collector = MetricsCollector::new();
        collector.record_request("p1", 100, 500);

        let json = serde_json::to_string(&collector).unwrap();
        let deserialized: MetricsCollector = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_requests, 1);
        assert!(deserialized.providers.contains_key("p1"));
    }
}
