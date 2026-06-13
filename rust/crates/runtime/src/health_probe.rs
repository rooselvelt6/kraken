use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct LatencyWindow {
    samples: VecDeque<f64>,
    max_samples: usize,
}

impl LatencyWindow {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
        }
    }

    pub fn record(&mut self, latency_ms: f64) {
        self.samples.push_back(latency_ms);
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    pub fn percentile(&self, p: f64) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<f64> = self.samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((sorted.len() as f64) * p / 100.0).ceil() as usize - 1;
        Some(sorted[idx.min(sorted.len() - 1)])
    }

    pub fn p50(&self) -> Option<f64> {
        self.percentile(50.0)
    }

    pub fn p95(&self) -> Option<f64> {
        self.percentile(95.0)
    }

    pub fn p99(&self) -> Option<f64> {
        self.percentile(99.0)
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn average(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let sum: f64 = self.samples.iter().sum();
        Some(sum / self.samples.len() as f64)
    }

    pub fn max(&self) -> Option<f64> {
        self.samples.iter().copied().max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub name: String,
    pub interval: Duration,
    pub last_probe: Option<Instant>,
    pub consecutive_failures: u64,
    pub consecutive_successes: u64,
    pub total_probes: u64,
    pub failed_probes: u64,
    pub status: HealthStatus,
    pub latency_window: LatencyWindow,
    pub timeout_threshold_ms: f64,
}

impl ProbeTarget {
    pub fn new(name: &str, interval: Duration, timeout_threshold_ms: f64) -> Self {
        Self {
            name: name.to_string(),
            interval,
            last_probe: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            total_probes: 0,
            failed_probes: 0,
            status: HealthStatus::Unknown,
            latency_window: LatencyWindow::new(100),
            timeout_threshold_ms,
        }
    }

    pub fn due_for_probe(&self) -> bool {
        match self.last_probe {
            None => true,
            Some(last) => last.elapsed() >= self.interval,
        }
    }

    pub fn record_success(&mut self, latency_ms: f64) {
        self.total_probes += 1;
        self.consecutive_failures = 0;
        self.consecutive_successes += 1;
        self.last_probe = Some(Instant::now());
        self.latency_window.record(latency_ms);

        if latency_ms > self.timeout_threshold_ms {
            self.status = HealthStatus::Degraded;
        } else if self.consecutive_successes >= 3 {
            self.status = HealthStatus::Healthy;
        }
    }

    pub fn record_failure(&mut self, latency_ms: f64) {
        self.total_probes += 1;
        self.failed_probes += 1;
        self.consecutive_failures += 1;
        self.consecutive_successes = 0;
        self.last_probe = Some(Instant::now());
        self.latency_window.record(latency_ms);

        if self.consecutive_failures >= 5 {
            self.status = HealthStatus::Unhealthy;
        } else if self.consecutive_failures >= 2 {
            self.status = HealthStatus::Degraded;
        }

        if latency_ms > self.timeout_threshold_ms && self.consecutive_failures >= 3 {
            self.status = HealthStatus::Unhealthy;
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self.status, HealthStatus::Unknown | HealthStatus::Healthy | HealthStatus::Degraded)
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_probes == 0 {
            0.0
        } else {
            self.failed_probes as f64 / self.total_probes as f64
        }
    }

    pub fn report(&self) -> ProbeReport {
        ProbeReport {
            name: self.name.clone(),
            status: self.status,
            p50_ms: self.latency_window.p50(),
            p95_ms: self.latency_window.p95(),
            p99_ms: self.latency_window.p99(),
            avg_ms: self.latency_window.average(),
            max_ms: self.latency_window.max(),
            error_rate: self.error_rate(),
            total_probes: self.total_probes,
            consecutive_failures: self.consecutive_failures,
            consecutive_successes: self.consecutive_successes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub name: String,
    pub status: HealthStatus,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub error_rate: f64,
    pub total_probes: u64,
    pub consecutive_failures: u64,
    pub consecutive_successes: u64,
}

impl ProbeReport {
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy)
    }

    pub fn should_degrade(&self) -> bool {
        self.p95_ms.map_or(false, |p95| p95 > 5000.0)
            || self.p99_ms.map_or(false, |p99| p99 > 10000.0)
            || self.error_rate > 0.1
            || self.consecutive_failures >= 3
    }

    pub fn should_open_circuit(&self) -> bool {
        self.p99_ms.map_or(false, |p99| p99 > 10000.0)
            || self.error_rate > 0.5
            || self.consecutive_failures >= 5
    }
}

pub struct HealthProbeRegistry {
    targets: HashMap<String, ProbeTarget>,
}

impl HealthProbeRegistry {
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
        }
    }

    pub fn register(&mut self, target: ProbeTarget) {
        self.targets.insert(target.name.clone(), target);
    }

    pub fn get(&self, name: &str) -> Option<&ProbeTarget> {
        self.targets.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut ProbeTarget> {
        self.targets.get_mut(name)
    }

    pub fn record_success(&mut self, name: &str, latency_ms: f64) {
        if let Some(target) = self.targets.get_mut(name) {
            target.record_success(latency_ms);
        }
    }

    pub fn record_failure(&mut self, name: &str, latency_ms: f64) {
        if let Some(target) = self.targets.get_mut(name) {
            target.record_failure(latency_ms);
        }
    }

    pub fn due_targets(&self) -> Vec<String> {
        self.targets
            .values()
            .filter(|t| t.due_for_probe())
            .map(|t| t.name.clone())
            .collect()
    }

    pub fn reports(&self) -> Vec<ProbeReport> {
        self.targets.values().map(|t| t.report()).collect()
    }

    pub fn report_for(&self, name: &str) -> Option<ProbeReport> {
        self.targets.get(name).map(|t| t.report())
    }

    pub fn unhealthy_targets(&self) -> Vec<String> {
        self.targets
            .values()
            .filter(|t| t.status == HealthStatus::Unhealthy)
            .map(|t| t.name.clone())
            .collect()
    }

    pub fn degraded_targets(&self) -> Vec<String> {
        self.targets
            .values()
            .filter(|t| t.status == HealthStatus::Degraded)
            .map(|t| t.name.clone())
            .collect()
    }

    pub fn remove(&mut self, name: &str) {
        self.targets.remove(name);
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProbeTarget> {
        self.targets.values()
    }
}

static GLOBAL_HEALTH_REGISTRY: OnceLock<Mutex<HealthProbeRegistry>> = OnceLock::new();

pub fn global_health_registry() -> &'static Mutex<HealthProbeRegistry> {
    GLOBAL_HEALTH_REGISTRY.get_or_init(|| {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new(
            "anthropic",
            Duration::from_secs(5),
            10_000.0,
        ));
        registry.register(ProbeTarget::new(
            "deepseek",
            Duration::from_secs(5),
            10_000.0,
        ));
        registry.register(ProbeTarget::new(
            "bigpickle",
            Duration::from_secs(5),
            10_000.0,
        ));
        registry.register(ProbeTarget::new(
            "ollama",
            Duration::from_secs(5),
            30_000.0,
        ));
        Mutex::new(registry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_window_percentiles() {
        let mut window = LatencyWindow::new(10);
        window.record(10.0);
        window.record(20.0);
        window.record(30.0);
        window.record(40.0);
        window.record(50.0);

        assert_eq!(window.p50(), Some(30.0));
        assert_eq!(window.p95(), Some(50.0));
        assert_eq!(window.p99(), Some(50.0));
    }

    #[test]
    fn test_latency_window_empty() {
        let window = LatencyWindow::new(10);
        assert!(window.p50().is_none());
        assert!(window.average().is_none());
    }

    #[test]
    fn test_latency_window_average() {
        let mut window = LatencyWindow::new(10);
        window.record(10.0);
        window.record(20.0);
        window.record(30.0);
        assert!((window.average().unwrap() - 20.0).abs() < 0.001);
    }

    #[test]
    fn test_latency_window_max_capacity() {
        let mut window = LatencyWindow::new(3);
        window.record(1.0);
        window.record(2.0);
        window.record(3.0);
        window.record(4.0);
        assert_eq!(window.len(), 3);
        assert_eq!(window.max(), Some(4.0));
    }

    #[test]
    fn test_probe_target_initial_state() {
        let target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        assert_eq!(target.status, HealthStatus::Unknown);
        assert!(target.due_for_probe());
        assert!(target.is_available());
    }

    #[test]
    fn test_probe_target_success_healthy() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        target.record_success(100.0);
        assert_eq!(target.status, HealthStatus::Unknown);
        assert_eq!(target.consecutive_successes, 1);
        target.record_success(100.0);
        target.record_success(100.0);
        assert_eq!(target.status, HealthStatus::Healthy);
        assert_eq!(target.consecutive_successes, 3);
    }

    #[test]
    fn test_probe_target_latency_degraded() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 500.0);
        target.record_success(600.0);
        assert_eq!(target.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_probe_target_consecutive_failures_unhealthy() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        for _ in 0..5 {
            target.record_failure(1000.0);
        }
        assert_eq!(target.status, HealthStatus::Unhealthy);
        assert!(!target.is_available());
    }

    #[test]
    fn test_probe_target_consecutive_failures_degraded() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        target.record_failure(1000.0);
        assert_eq!(target.status, HealthStatus::Unknown);
        target.record_failure(1000.0);
        assert_eq!(target.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_probe_target_error_rate() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        assert_eq!(target.error_rate(), 0.0);
        target.record_success(100.0);
        target.record_failure(100.0);
        assert!((target.error_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_probe_target_not_due_after_probe() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(3600), 10_000.0);
        target.record_success(100.0);
        assert!(!target.due_for_probe());
    }

    #[test]
    fn test_probe_report_is_healthy() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        target.record_success(100.0);
        target.record_success(100.0);
        target.record_success(100.0);
        let report = target.report();
        assert!(report.is_healthy());
    }

    #[test]
    fn test_probe_report_should_degrade() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        for _ in 0..10 {
            target.record_success(6000.0);
        }
        let report = target.report();
        assert!(report.should_degrade());
    }

    #[test]
    fn test_probe_report_should_open_circuit() {
        let mut target = ProbeTarget::new("test", Duration::from_secs(5), 10_000.0);
        for _ in 0..6 {
            target.record_failure(12000.0);
        }
        let report = target.report();
        assert!(report.should_open_circuit());
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        assert!(registry.get("p1").is_some());
        assert!(registry.get("p2").is_none());
    }

    #[test]
    fn test_registry_record_success() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        registry.record_success("p1", 100.0);
        let target = registry.get("p1").unwrap();
        assert_eq!(target.total_probes, 1);
    }

    #[test]
    fn test_registry_record_failure() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        registry.record_failure("p1", 1000.0);
        let target = registry.get("p1").unwrap();
        assert_eq!(target.total_probes, 1);
        assert_eq!(target.failed_probes, 1);
    }

    #[test]
    fn test_registry_due_targets() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        let due = registry.due_targets();
        assert_eq!(due, vec!["p1".to_string()]);
    }

    #[test]
    fn test_registry_reports() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        registry.record_success("p1", 100.0);
        let reports = registry.reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].name, "p1");
    }

    #[test]
    fn test_registry_unhealthy_targets() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        for _ in 0..5 {
            registry.record_failure("p1", 1000.0);
        }
        let unhealthy = registry.unhealthy_targets();
        assert_eq!(unhealthy, vec!["p1".to_string()]);
    }

    #[test]
    fn test_registry_remove() {
        let mut registry = HealthProbeRegistry::new();
        registry.register(ProbeTarget::new("p1", Duration::from_secs(5), 10_000.0));
        assert!(registry.get("p1").is_some());
        registry.remove("p1");
        assert!(registry.get("p1").is_none());
    }

    #[test]
    fn test_global_registry_init() {
        let registry = global_health_registry();
        let guard = registry.lock().unwrap();
        let report = guard.report_for("anthropic");
        assert!(report.is_some());
        assert_eq!(report.unwrap().name, "anthropic");
    }
}
