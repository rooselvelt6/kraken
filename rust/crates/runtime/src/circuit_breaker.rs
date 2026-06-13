use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    HalfOpen,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitLevel {
    Provider,
    Tool,
    McpServer,
    Global,
}

impl CircuitLevel {
    pub fn parent(&self) -> Option<Self> {
        match self {
            Self::Tool => Some(Self::Provider),
            Self::Provider => Some(Self::Global),
            Self::McpServer => Some(Self::Global),
            Self::Global => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitNode {
    pub name: String,
    pub level: CircuitLevel,
    pub state: CircuitState,
    pub failure_threshold: u64,
    pub recovery_timeout: Duration,
    pub success_threshold: u64,
    half_open_successes: u64,
    failure_count: u64,
    success_count: u64,
    last_failure: Option<Instant>,
    last_success: Option<Instant>,
    opened_at: Option<Instant>,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    latencies: Vec<f64>,
    max_latency_samples: usize,
    consecutive_timeouts: u64,
    open_count: u64,
}

impl CircuitNode {
    pub fn new(name: &str, level: CircuitLevel, failure_threshold: u64, recovery_timeout: Duration) -> Self {
        Self {
            name: name.to_string(),
            level,
            state: CircuitState::Closed,
            failure_threshold,
            recovery_timeout,
            success_threshold: 2,
            half_open_successes: 0,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            last_success: None,
            opened_at: None,
            latency_p50_ms: 0.0,
            latency_p95_ms: 0.0,
            latency_p99_ms: 0.0,
            latencies: Vec::with_capacity(100),
            max_latency_samples: 100,
            consecutive_timeouts: 0,
            open_count: 0,
        }
    }

    pub fn can_execute(&self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                if let Some(opened) = self.opened_at {
                    let elapsed = opened.elapsed();
                    if elapsed >= self.recovery_timeout {
                        return true;
                    }
                }
                false
            }
        }
    }

    pub fn record_success(&mut self, latency_ms: f64) {
        self.success_count += 1;
        self.last_success = Some(Instant::now());
        self.consecutive_timeouts = 0;

        self.latencies.push(latency_ms);
        if self.latencies.len() > self.max_latency_samples {
            self.latencies.remove(0);
        }
        self.compute_latency_percentiles();

        match self.state {
            CircuitState::Open => {
                if self.should_attempt_recovery() {
                    self.state = CircuitState::HalfOpen;
                    self.half_open_successes = 1;
                    if self.half_open_successes >= self.success_threshold {
                        self.state = CircuitState::Closed;
                        self.failure_count = 0;
                        self.half_open_successes = 0;
                        self.opened_at = None;
                    }
                }
            }
            CircuitState::HalfOpen => {
                self.half_open_successes += 1;
                if self.half_open_successes >= self.success_threshold {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.half_open_successes = 0;
                    self.opened_at = None;
                }
            }
            CircuitState::Closed => {
                self.failure_count = 0;
            }
        }
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());

        match self.state {
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.opened_at = Some(Instant::now());
                self.open_count += 1;
                self.half_open_successes = 0;
            }
            CircuitState::Closed => {
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitState::Open;
                    self.opened_at = Some(Instant::now());
                    self.open_count += 1;
                }
            }
            CircuitState::Open => {
                self.opened_at = Some(Instant::now());
            }
        }
    }

    pub fn record_timeout(&mut self, latency_ms: f64) {
        self.consecutive_timeouts += 1;
        self.record_failure();
        self.latencies.push(latency_ms);
        if self.latencies.len() > self.max_latency_samples {
            self.latencies.remove(0);
        }
        self.compute_latency_percentiles();
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.state, CircuitState::Closed)
    }

    pub fn failure_rate(&self) -> f64 {
        let total = self.failure_count + self.success_count;
        if total == 0 {
            0.0
        } else {
            self.failure_count as f64 / total as f64
        }
    }

    pub fn recovery_time_remaining(&self) -> Option<Duration> {
        if matches!(self.state, CircuitState::Open) {
            self.opened_at.map(|opened| {
                let elapsed = opened.elapsed();
                if elapsed >= self.recovery_timeout {
                    Duration::ZERO
                } else {
                    self.recovery_timeout - elapsed
                }
            })
        } else {
            None
        }
    }

    fn should_attempt_recovery(&self) -> bool {
        self.opened_at.map_or(false, |opened| opened.elapsed() >= self.recovery_timeout)
    }

    pub fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.half_open_successes = 0;
        self.opened_at = None;
        self.consecutive_timeouts = 0;
    }

    fn compute_latency_percentiles(&mut self) {
        if self.latencies.is_empty() {
            return;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let len = sorted.len();

        let p50_idx = ((len as f64) * 0.50).ceil() as usize - 1;
        let p95_idx = ((len as f64) * 0.95).ceil() as usize - 1;
        let p99_idx = ((len as f64) * 0.99).ceil() as usize - 1;

        self.latency_p50_ms = sorted[p50_idx.min(len - 1)];
        self.latency_p95_ms = sorted[p95_idx.min(len - 1)];
        self.latency_p99_ms = sorted[p99_idx.min(len - 1)];
    }
}

#[derive(Debug, Clone)]
pub struct CircuitForest {
    nodes: HashMap<String, CircuitNode>,
    parent_map: HashMap<String, Option<String>>,
}

impl CircuitForest {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            parent_map: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        name: &str,
        level: CircuitLevel,
        failure_threshold: u64,
        recovery_timeout: Duration,
    ) {
        let node = CircuitNode::new(name, level, failure_threshold, recovery_timeout);
        self.nodes.insert(name.to_string(), node);

        let parent_name = level.parent().map(|p| match p {
            CircuitLevel::Global => "global".to_string(),
            CircuitLevel::Provider => name.split_once('.').map_or("global".to_string(), |(p, _)| p.to_string()),
            CircuitLevel::Tool => name.split_once('.').map_or("global".to_string(), |(p, _)| p.to_string()),
            CircuitLevel::McpServer => "mcp".to_string(),
        });
        self.parent_map.insert(name.to_string(), parent_name);
    }

    pub fn get(&self, name: &str) -> Option<&CircuitNode> {
        self.nodes.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut CircuitNode> {
        self.nodes.get_mut(name)
    }

    pub fn record_success(&mut self, name: &str, latency_ms: f64) {
        if let Some(node) = self.nodes.get_mut(name) {
            node.record_success(latency_ms);
        }
    }

    pub fn record_failure(&mut self, name: &str) {
        if let Some(node) = self.nodes.get_mut(name) {
            node.record_failure();
            if node.state == CircuitState::Open {
                if let Some(parent) = self.parent_map.get(name).and_then(|p| p.as_ref().cloned()) {
                    if let Some(pnode) = self.nodes.get_mut(&parent) {
                        pnode.record_failure();
                    }
                }
            }
        }
    }

    pub fn can_execute(&self, name: &str) -> bool {
        if let Some(node) = self.nodes.get(name) {
            if !node.can_execute() {
                return false;
            }
            if let Some(parent) = self.parent_map.get(name).and_then(|p| p.as_ref()) {
                if let Some(pnode) = self.nodes.get(parent) {
                    if !pnode.can_execute() {
                        return false;
                    }
                }
            }
            true
        } else {
            true
        }
    }

    pub fn is_healthy(&self, name: &str) -> bool {
        self.nodes.get(name).map_or(true, |n| n.is_healthy())
    }

    pub fn degraded_providers(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|(_, n)| !n.is_healthy())
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn open_circuits(&self) -> Vec<&CircuitNode> {
        self.nodes
            .values()
            .filter(|n| matches!(n.state, CircuitState::Open))
            .collect()
    }

    pub fn reset(&mut self, name: &str) {
        if let Some(node) = self.nodes.get_mut(name) {
            node.reset();
        }
    }
}

static CIRCUIT_FOREST: OnceLock<Mutex<CircuitForest>> = OnceLock::new();

pub fn global_circuit_forest() -> &'static Mutex<CircuitForest> {
    CIRCUIT_FOREST.get_or_init(|| {
        let mut forest = CircuitForest::new();
        forest.register("global", CircuitLevel::Global, 3, Duration::from_secs(60));
        forest.register("mcp", CircuitLevel::McpServer, 3, Duration::from_secs(30));
        Mutex::new(forest)
    })
}

pub fn init_circuit_forest(providers: &[&str], tools: &[(&str, &str)], mcp_servers: &[&str]) {
    let mut forest = CIRCUIT_FOREST
        .get_or_init(|| Mutex::new(CircuitForest::new()))
        .lock()
        .unwrap();

    forest.register("global", CircuitLevel::Global, 3, Duration::from_secs(60));

    for provider in providers {
        forest.register(
            provider,
            CircuitLevel::Provider,
            5,
            Duration::from_secs(30),
        );
    }

    for (provider, tool) in tools {
        forest.register(
            &format!("{provider}.{tool}"),
            CircuitLevel::Tool,
            3,
            Duration::from_secs(15),
        );
    }

    for server in mcp_servers {
        forest.register(server, CircuitLevel::McpServer, 3, Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_node_default_state() {
        let node = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
        assert_eq!(node.state, CircuitState::Closed);
        assert!(node.can_execute());
    }

    #[test]
    fn test_circuit_opens_after_failures() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
        node.record_failure();
        node.record_failure();
        node.record_failure();
        assert_eq!(node.state, CircuitState::Open);
        assert!(!node.can_execute());
    }

    #[test]
    fn test_circuit_stays_closed_below_threshold() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 5, Duration::from_secs(30));
        node.record_failure();
        node.record_failure();
        assert_eq!(node.state, CircuitState::Closed);
        assert!(node.can_execute());
    }

    #[test]
    fn test_circuit_recovers_after_timeout() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 2, Duration::from_millis(1));
        node.record_failure();
        node.record_failure();
        assert_eq!(node.state, CircuitState::Open);
        std::thread::sleep(Duration::from_millis(2));
        assert!(node.can_execute());
    }

    #[test]
    fn test_half_open_transitions_to_closed_on_successes() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 2, Duration::from_millis(1));
        node.record_failure();
        node.record_failure();
        assert_eq!(node.state, CircuitState::Open);
        std::thread::sleep(Duration::from_millis(2));
        assert!(node.can_execute());
        node.record_success(10.0);
        assert_eq!(node.state, CircuitState::HalfOpen);
        node.record_success(10.0);
        assert_eq!(node.state, CircuitState::Closed);
    }

    #[test]
    fn test_half_open_fails_back_to_open() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 2, Duration::from_millis(1));
        node.record_failure();
        node.record_failure();
        std::thread::sleep(Duration::from_millis(2));
        assert!(node.can_execute());
        node.record_success(10.0);
        assert_eq!(node.state, CircuitState::HalfOpen);
        node.record_failure();
        assert_eq!(node.state, CircuitState::Open);
    }

    #[test]
    fn test_latency_percentiles() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
        let latencies = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0];
        for l in latencies {
            node.record_success(l);
        }
        assert!(node.latency_p50_ms > 0.0);
        assert!(node.latency_p95_ms >= node.latency_p50_ms);
        assert!(node.latency_p99_ms >= node.latency_p95_ms);
    }

    #[test]
    fn test_failure_rate() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
        assert_eq!(node.failure_rate(), 0.0);
        node.record_failure();
        node.record_failure();
        assert!((node.failure_rate() - 1.0).abs() < 0.001);
        node.record_success(10.0);
        assert_eq!(node.failure_count, 0);
    }

    #[test]
    fn test_recovery_time_remaining() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 1, Duration::from_secs(3600));
        node.record_failure();
        let remaining = node.recovery_time_remaining();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > Duration::from_secs(3500));
    }

    #[test]
    fn test_no_recovery_time_when_closed() {
        let node = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
        assert!(node.recovery_time_remaining().is_none());
    }

    #[test]
    fn test_circuit_forest_register() {
        let mut forest = CircuitForest::new();
        forest.register("test-provider", CircuitLevel::Provider, 5, Duration::from_secs(30));
        assert!(forest.get("test-provider").is_some());
    }

    #[test]
    fn test_circuit_forest_hierarchical_failure() {
        let mut forest = CircuitForest::new();
        forest.register("global", CircuitLevel::Global, 3, Duration::from_secs(60));
        forest.register("provider1", CircuitLevel::Provider, 3, Duration::from_secs(30));

        assert!(forest.can_execute("provider1"));

        forest.record_failure("provider1");
        forest.record_failure("provider1");
        forest.record_failure("provider1");

        assert!(!forest.can_execute("provider1"));
    }

    #[test]
    fn test_circuit_forest_degraded_providers() {
        let mut forest = CircuitForest::new();
        forest.register("p1", CircuitLevel::Provider, 1, Duration::from_secs(3600));
        forest.register("p2", CircuitLevel::Provider, 1, Duration::from_secs(3600));
        forest.record_failure("p1");

        let degraded = forest.degraded_providers();
        assert!(degraded.contains(&"p1".to_string()));
        assert!(!degraded.contains(&"p2".to_string()));
    }

    #[test]
    fn test_circuit_forest_open_circuits() {
        let mut forest = CircuitForest::new();
        forest.register("p1", CircuitLevel::Provider, 1, Duration::from_secs(3600));
        forest.register("p2", CircuitLevel::Provider, 1, Duration::from_secs(3600));
        forest.record_failure("p1");

        let open = forest.open_circuits();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].name, "p1");
    }

    #[test]
    fn test_circuit_forest_reset() {
        let mut forest = CircuitForest::new();
        forest.register("p1", CircuitLevel::Provider, 1, Duration::from_secs(3600));
        forest.record_failure("p1");
        assert!(!forest.is_healthy("p1"));
        forest.reset("p1");
        assert!(forest.is_healthy("p1"));
    }

    #[test]
    fn test_global_singleton() {
        let forest = global_circuit_forest();
        let guard = forest.lock().unwrap();
        assert!(guard.get("global").is_some());
    }

    #[test]
    fn test_consecutive_timeouts() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 1, Duration::from_secs(3600));
        node.record_timeout(5000.0);
        assert_eq!(node.consecutive_timeouts, 1);
        assert_eq!(node.state, CircuitState::Open);
    }

    #[test]
    fn test_success_clears_consecutive_timeouts() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
        node.record_timeout(5000.0);
        node.record_timeout(5000.0);
        assert_eq!(node.consecutive_timeouts, 2);
        node.record_success(10.0);
        assert_eq!(node.consecutive_timeouts, 0);
    }

    #[test]
    fn test_open_count_increments() {
        let mut node = CircuitNode::new("test", CircuitLevel::Tool, 2, Duration::from_millis(1));
        node.record_failure();
        node.record_failure();
        assert_eq!(node.open_count, 1);
        std::thread::sleep(Duration::from_millis(2));
        node.record_success(10.0);
        node.record_success(10.0);
        assert_eq!(node.state, CircuitState::Closed);
        node.record_failure();
        node.record_failure();
        assert_eq!(node.open_count, 2);
    }
}
