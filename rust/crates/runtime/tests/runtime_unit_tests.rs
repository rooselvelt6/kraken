use std::time::Duration;
use runtime::*;
use runtime::self_healing::*;
use runtime::concurrency::*;
use runtime::circuit_breaker::*;
use runtime::rate_limiter::*;
use runtime::green_contract::{GreenContract, GreenContractOutcome};
use runtime::green_contract::GreenLevel as GreenContractLevel;
use runtime::forensic::*;
use runtime::health_probe::*;
use runtime::size_budget::*;
use runtime::provider_chain::*;
use runtime::siem_export::*;
use runtime::mcp_tool_bridge::*;
use runtime::lsp_client::*;

// ---------------------------------------------------------------------------
// self_healing
// ---------------------------------------------------------------------------

#[test]
fn self_healing_wal_entry_default() {
    let e = WalEntry {
        sequence: 0,
        timestamp_ms: 0,
        operation: String::new(),
        data: serde_json::json!(null),
    };
    assert_eq!(e.sequence, 0);
    assert_eq!(e.operation, "");
}

#[test]
fn self_healing_wal_entry_serde_roundtrip() {
    let e = WalEntry {
        sequence: 42,
        timestamp_ms: 1234,
        operation: "op".into(),
        data: serde_json::json!({"k": "v"}),
    };
    let j = serde_json::to_string(&e).unwrap();
    let back: WalEntry = serde_json::from_str(&j).unwrap();
    assert_eq!(back.sequence, 42);
    assert_eq!(back.data["k"], "v");
}

#[test]
fn self_healing_session_snapshot_serde_roundtrip() {
    let s = SessionSnapshot {
        session_id: "s1".into(),
        timestamp_ms: 99,
        message_count: 5,
        checkpoints_count: 2,
        checksum: "abc".into(),
        data: serde_json::json!({"x": 1}),
    };
    let j = serde_json::to_string(&s).unwrap();
    let back: SessionSnapshot = serde_json::from_str(&j).unwrap();
    assert_eq!(back.session_id, "s1");
    assert_eq!(back.message_count, 5);
}

#[test]
fn self_healing_checkpoint_manifest_serde_roundtrip() {
    let m = CheckpointManifest {
        session_id: "s".into(),
        last_sequence: 10,
        snapshot_path: "/a".into(),
        wal_path: "/b".into(),
        snapshot_checksum: "cs".into(),
        created_at_ms: 100,
        message_count: 3,
    };
    let j = serde_json::to_string(&m).unwrap();
    let back: CheckpointManifest = serde_json::from_str(&j).unwrap();
    assert_eq!(back.last_sequence, 10);
}

#[test]
fn self_healing_backoff_strategy_default() {
    let b = BackoffStrategy::default();
    assert_eq!(b.initial_delay, INITIAL_BACKOFF);
    assert_eq!(b.max_delay, MAX_BACKOFF);
    assert!((b.multiplier - 2.0).abs() < f64::EPSILON);
    assert!((b.jitter - 0.1).abs() < f64::EPSILON);
}

#[test]
fn self_healing_restartable_component_new() {
    let c = RestartableComponent::new("test");
    assert_eq!(c.name, "test");
    assert_eq!(c.attempt, 0);
    assert!(c.last_restart.is_none());
    assert!(!c.should_escalate());
}

#[test]
fn self_healing_restartable_component_record_attempt() {
    let mut c = RestartableComponent::new("test");
    let d = c.record_attempt();
    assert_eq!(c.attempt, 1);
    assert!(c.last_restart.is_some());
    assert!(d.as_secs() >= 1);
}

#[test]
fn self_healing_restartable_component_escalation() {
    let mut c = RestartableComponent::new("t");
    c.max_attempts = 2;
    c.record_attempt();
    assert!(!c.should_escalate());
    c.record_attempt();
    assert!(c.should_escalate());
}

#[test]
fn self_healing_restartable_component_reset() {
    let mut c = RestartableComponent::new("t");
    c.record_attempt();
    c.reset();
    assert_eq!(c.attempt, 0);
    assert!(c.last_restart.is_none());
    assert!(!c.should_escalate());
}

#[test]
fn self_healing_shutdown_actions_default() {
    let a = ShutdownActions::default();
    assert!(a.should_flush_audit);
    assert!(a.should_checkpoint);
    assert!(a.should_close_mcp);
    assert!(a.should_zeroize);
}

#[test]
fn self_healing_shutdown_result_serde_roundtrip() {
    let r = ShutdownResult {
        success: true,
        elapsed_ms: 42,
        message: "done".into(),
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: ShutdownResult = serde_json::from_str(&j).unwrap();
    assert!(back.success);
    assert_eq!(back.elapsed_ms, 42);
}

#[test]
fn self_healing_system_metrics_memory_critical() {
    let m = SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 50,
        memory_total_kb: 10000,
        disk_free_kb: 0,
        disk_total_kb: 0,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(m.is_memory_critical());
}

#[test]
fn self_healing_system_metrics_memory_not_critical() {
    let m = SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 1000,
        memory_total_kb: 10000,
        disk_free_kb: 0,
        disk_total_kb: 0,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(!m.is_memory_critical());
}

#[test]
fn self_healing_system_metrics_memory_zero_total() {
    let m = SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 0,
        memory_total_kb: 0,
        disk_free_kb: 0,
        disk_total_kb: 0,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(!m.is_memory_critical());
}

#[test]
fn self_healing_system_metrics_disk_critical() {
    let m = SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 0,
        memory_total_kb: 0,
        disk_free_kb: 100,
        disk_total_kb: 10000,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(m.is_disk_critical());
}

#[test]
fn self_healing_system_metrics_disk_not_critical() {
    let m = SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 0,
        memory_total_kb: 0,
        disk_free_kb: 500,
        disk_total_kb: 10000,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(!m.is_disk_critical());
}

#[test]
fn self_healing_system_metrics_disk_zero_total() {
    let m = SystemMetrics {
        timestamp_ms: 0,
        memory_available_kb: 0,
        memory_total_kb: 0,
        disk_free_kb: 0,
        disk_total_kb: 0,
        uptime_secs: 0,
        num_probes_healthy: 0,
        num_probes_degraded: 0,
        num_probes_unhealthy: 0,
    };
    assert!(!m.is_disk_critical());
}

#[test]
fn self_healing_system_metrics_serde_roundtrip() {
    let m = SystemMetrics {
        timestamp_ms: 100,
        memory_available_kb: 500,
        memory_total_kb: 1000,
        disk_free_kb: 2000,
        disk_total_kb: 4000,
        uptime_secs: 3600,
        num_probes_healthy: 3,
        num_probes_degraded: 1,
        num_probes_unhealthy: 0,
    };
    let j = serde_json::to_string(&m).unwrap();
    let back: SystemMetrics = serde_json::from_str(&j).unwrap();
    assert_eq!(back.uptime_secs, 3600);
}

#[test]
fn self_healing_component_health_variants() {
    assert_eq!(ComponentHealth::Unknown as u8, ComponentHealth::Unknown as u8);
    assert_ne!(ComponentHealth::Healthy, ComponentHealth::Unhealthy);
    assert_eq!(ComponentHealth::Degraded, ComponentHealth::Degraded);
}

#[test]
fn self_healing_health_report_is_healthy() {
    let r = HealthReport {
        timestamp_ms: 0,
        system: SystemMetrics {
            timestamp_ms: 0,
            memory_available_kb: 0,
            memory_total_kb: 0,
            disk_free_kb: 0,
            disk_total_kb: 0,
            uptime_secs: 0,
            num_probes_healthy: 0,
            num_probes_degraded: 0,
            num_probes_unhealthy: 0,
        },
        components: vec![],
        all_healthy: true,
        degraded_count: 0,
        unhealthy_count: 0,
    };
    assert!(r.is_healthy());
    assert!(!r.has_degraded());
    assert!(!r.has_unhealthy());
}

#[test]
fn self_healing_health_report_not_healthy() {
    let r = HealthReport {
        timestamp_ms: 0,
        system: SystemMetrics {
            timestamp_ms: 0,
            memory_available_kb: 0,
            memory_total_kb: 0,
            disk_free_kb: 0,
            disk_total_kb: 0,
            uptime_secs: 0,
            num_probes_healthy: 0,
            num_probes_degraded: 1,
            num_probes_unhealthy: 1,
        },
        components: vec![],
        all_healthy: false,
        degraded_count: 1,
        unhealthy_count: 1,
    };
    assert!(!r.is_healthy());
    assert!(r.has_degraded());
    assert!(r.has_unhealthy());
}

#[test]
fn self_healing_health_report_serde_roundtrip() {
    let r = HealthReport {
        timestamp_ms: 50,
        system: SystemMetrics {
            timestamp_ms: 0,
            memory_available_kb: 0,
            memory_total_kb: 0,
            disk_free_kb: 0,
            disk_total_kb: 0,
            uptime_secs: 0,
            num_probes_healthy: 0,
            num_probes_degraded: 0,
            num_probes_unhealthy: 0,
        },
        components: vec![],
        all_healthy: true,
        degraded_count: 0,
        unhealthy_count: 0,
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: HealthReport = serde_json::from_str(&j).unwrap();
    assert!(back.all_healthy);
}

#[test]
fn self_healing_health_monitor_new_default() {
    let m = HealthMonitor::new();
    assert_eq!(m.component_health("nonexistent"), ComponentHealth::Unknown);
}

#[test]
fn self_healing_health_monitor_register_and_heartbeat() {
    let m = HealthMonitor::new();
    m.register_component("svc");
    assert_eq!(m.component_health("svc"), ComponentHealth::Unknown);
    m.report_heartbeat("svc");
    assert_eq!(m.component_health("svc"), ComponentHealth::Healthy);
}

#[test]
fn self_healing_health_monitor_failure() {
    let m = HealthMonitor::new();
    m.register_component("svc");
    m.report_failure("svc", "err");
    assert_eq!(m.component_health("svc"), ComponentHealth::Unhealthy);
}

#[test]
fn self_healing_health_monitor_degraded() {
    let m = HealthMonitor::new();
    m.register_component("svc");
    m.report_degraded("svc", "slow");
    assert_eq!(m.component_health("svc"), ComponentHealth::Degraded);
}

#[test]
fn self_healing_health_monitor_mark_healthy() {
    let m = HealthMonitor::new();
    m.register_component("svc");
    m.report_failure("svc", "err");
    m.mark_healthy("svc");
    assert_eq!(m.component_health("svc"), ComponentHealth::Healthy);
}

#[test]
fn self_healing_health_monitor_report() {
    let m = HealthMonitor::new();
    m.register_component("a");
    m.register_component("b");
    m.report_heartbeat("a");
    m.report_failure("b", "err");
    let r = m.report();
    assert!(!r.all_healthy);
    assert_eq!(r.unhealthy_count, 1);
    assert_eq!(r.degraded_count, 0);
}

#[test]
fn self_healing_health_monitor_collect_metrics() {
    let m = HealthMonitor::new();
    let metrics = m.collect_metrics();
    assert!(metrics.timestamp_ms > 0);
}

#[test]
fn self_healing_graceful_shutdown_new() {
    let s = GracefulShutdown::new();
    assert!(!s.signal_received());
}

#[test]
fn self_healing_graceful_shutdown_with_actions() {
    let a = ShutdownActions {
        should_flush_audit: false,
        should_checkpoint: false,
        should_close_mcp: false,
        should_zeroize: false,
    };
    let s = GracefulShutdown::new().with_actions(a);
    assert!(!s.signal_received());
}

#[test]
fn self_healing_auto_restarter_new() {
    let r = AutoRestarter::new();
    assert!(r.registered_components().is_empty());
}

#[test]
fn self_healing_auto_restarter_register_and_attempt() {
    let r = AutoRestarter::new();
    r.register("mcp");
    assert_eq!(r.attempt_count("mcp"), 0);
    r.record_attempt("mcp");
    assert_eq!(r.attempt_count("mcp"), 1);
}

#[test]
fn self_healing_auto_restarter_mark_recovered() {
    let r = AutoRestarter::new();
    r.register("mcp");
    r.record_attempt("mcp");
    r.mark_recovered("mcp");
    assert_eq!(r.attempt_count("mcp"), 0);
    assert!(!r.should_escalate("mcp"));
}

#[test]
fn self_healing_auto_restarter_escalation() {
    let r = AutoRestarter::new();
    r.register("mcp");
    for _ in 0..5 {
        r.record_attempt("mcp");
    }
    assert!(r.should_escalate("mcp"));
}

#[test]
fn self_healing_auto_restarter_unknown_component() {
    let r = AutoRestarter::new();
    assert_eq!(r.attempt_count("unknown"), 0);
    assert!(!r.should_escalate("unknown"));
}

#[test]
fn self_healing_auto_restarter_registered_components() {
    let r = AutoRestarter::new();
    r.register("a");
    r.register("b");
    let mut names = r.registered_components();
    names.sort();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn self_healing_auto_restarter_with_health_monitor() {
    let h = std::sync::Arc::new(HealthMonitor::new());
    let r = AutoRestarter::new().with_health_monitor(h);
    r.register("svc");
    assert_eq!(r.attempt_count("svc"), 0);
}

#[test]
fn self_healing_corruption_repair_result_variants() {
    assert_eq!(RepairResult::FreshSession, RepairResult::FreshSession);
    assert_ne!(RepairResult::FreshSession, RepairResult::RepairedFromWal);
    assert_ne!(
        RepairResult::Failed("a".into()),
        RepairResult::Failed("b".into())
    );
}

#[test]
fn self_healing_orchestrator_shutdown() {
    let dir = std::env::temp_dir().join(format!("orch-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut orch = SelfHealingOrchestrator::new(&dir);
    orch.start();
    orch.heartbeat("runtime");
    let r = orch.shutdown("test");
    assert!(r.success);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_orchestrator_health_report() {
    let dir = std::env::temp_dir().join(format!("orch-hr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let orch = SelfHealingOrchestrator::new(&dir);
    let r = orch.health_report();
    assert!(r.all_healthy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_orchestrator_init_session() {
    let dir = std::env::temp_dir().join(format!("orch-init-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut orch = SelfHealingOrchestrator::new(&dir);
    orch.init_session("s1");
    assert!(orch.checkpointer.is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_orchestrator_attempt_restart() {
    let dir = std::env::temp_dir().join(format!("orch-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let orch = SelfHealingOrchestrator::new(&dir);
    orch.restarter.register("worker");
    let d = orch.attempt_restart("worker");
    assert!(d.as_millis() >= 0);
    assert_eq!(orch.restarter.attempt_count("worker"), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_orchestrator_mark_recovered() {
    let dir = std::env::temp_dir().join(format!("orch-rec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let orch = SelfHealingOrchestrator::new(&dir);
    orch.attempt_restart("worker");
    orch.mark_recovered("worker");
    assert_eq!(orch.restarter.attempt_count("worker"), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_healing_constants() {
    assert_eq!(DEFAULT_CHECKPOINT_INTERVAL_CALLS, 5);
    assert_eq!(DEFAULT_CHECKPOINT_INTERVAL_SECS, 60);
    assert_eq!(MAX_WAL_ENTRIES, 100);
    assert!(INITIAL_BACKOFF.as_secs() <= MAX_BACKOFF.as_secs());
}

#[test]
fn self_healing_checkpointer_session_id() {
    let dir = std::env::temp_dir().join(format!("cp-sid-{}", std::process::id()));
    let cp = SessionCheckpointer::new(&dir, "my-session");
    assert_eq!(cp.session_id(), "my-session");
    assert_eq!(cp.sequence_counter(), 0);
    assert!(cp.wal_entries().is_empty());
}

#[test]
fn self_healing_checkpointer_checkpoint_dir() {
    let dir = std::env::temp_dir().join(format!("cp-dir-{}", std::process::id()));
    let cp = SessionCheckpointer::new(&dir, "s");
    assert_eq!(cp.checkpoint_dir(), dir.as_path());
}

#[test]
fn self_healing_checkpointer_with_intervals() {
    let dir = std::env::temp_dir().join(format!("cp-int-{}", std::process::id()));
    let cp = SessionCheckpointer::new(&dir, "s").with_intervals(10, 120);
    assert_eq!(cp.session_id(), "s");
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

#[test]
fn concurrency_category_default_limits() {
    assert_eq!(ConcurrencyCategory::Bash.default_limit(), 5);
    assert_eq!(ConcurrencyCategory::Read.default_limit(), 20);
    assert_eq!(ConcurrencyCategory::Write.default_limit(), 3);
    assert_eq!(ConcurrencyCategory::Search.default_limit(), 2);
    assert_eq!(ConcurrencyCategory::Mcp.default_limit(), 10);
}

#[test]
fn concurrency_category_names() {
    assert_eq!(ConcurrencyCategory::Bash.name(), "bash");
    assert_eq!(ConcurrencyCategory::Read.name(), "read");
    assert_eq!(ConcurrencyCategory::Write.name(), "write");
    assert_eq!(ConcurrencyCategory::Search.name(), "search");
    assert_eq!(ConcurrencyCategory::Mcp.name(), "mcp");
}

#[test]
fn concurrency_category_equality() {
    assert_eq!(ConcurrencyCategory::Bash, ConcurrencyCategory::Bash);
    assert_ne!(ConcurrencyCategory::Bash, ConcurrencyCategory::Read);
}

#[test]
fn concurrency_category_hash() {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    m.insert(ConcurrencyCategory::Bash, 1);
    m.insert(ConcurrencyCategory::Read, 2);
    assert_eq!(m.len(), 2);
    assert_eq!(m[&ConcurrencyCategory::Bash], 1);
}

#[test]
fn concurrency_manager_new_default() {
    let mgr = ConcurrencyManager::new();
    assert_eq!(mgr.limit(ConcurrencyCategory::Bash), 5);
    assert_eq!(mgr.active_count(ConcurrencyCategory::Bash), 0);
    assert!(!mgr.is_throttled(ConcurrencyCategory::Bash));
}

#[test]
fn concurrency_manager_set_limit() {
    let mgr = ConcurrencyManager::new();
    mgr.set_limit(ConcurrencyCategory::Bash, 10);
    assert_eq!(mgr.limit(ConcurrencyCategory::Bash), 10);
}

#[test]
fn concurrency_manager_available_permits() {
    let mgr = ConcurrencyManager::new();
    assert_eq!(mgr.available_permits(ConcurrencyCategory::Bash), 5);
    mgr.set_limit(ConcurrencyCategory::Bash, 2);
    assert_eq!(mgr.available_permits(ConcurrencyCategory::Bash), 2);
}

#[test]
fn concurrency_status_struct() {
    let s = ConcurrencyStatus {
        name: "bash".into(),
        limit: 5,
        active: 2,
        available: 3,
        throttled: false,
    };
    assert_eq!(s.name, "bash");
    assert_eq!(s.available, 3);
}

#[tokio::test]
async fn concurrency_manager_try_acquire_and_drop() {
    let mgr = ConcurrencyManager::new();
    let guard = mgr.try_acquire(ConcurrencyCategory::Bash);
    assert!(guard.is_some());
    assert_eq!(mgr.active_count(ConcurrencyCategory::Bash), 1);
    drop(guard);
    assert_eq!(mgr.active_count(ConcurrencyCategory::Bash), 0);
}

#[tokio::test]
async fn concurrency_manager_acquire_returns_guard() {
    let mgr = ConcurrencyManager::new();
    let guard = mgr.acquire(ConcurrencyCategory::Read).await;
    assert!(guard.is_some());
    let g = guard.unwrap();
    assert_eq!(g.category(), ConcurrencyCategory::Read);
}

#[tokio::test]
async fn concurrency_manager_status() {
    let mgr = ConcurrencyManager::new();
    let statuses = mgr.status();
    assert_eq!(statuses.len(), 5);
}

#[tokio::test]
async fn concurrency_manager_throttled_at_limit() {
    let mgr = ConcurrencyManager::new();
    mgr.set_limit(ConcurrencyCategory::Bash, 1);
    let _g1 = mgr.try_acquire(ConcurrencyCategory::Bash);
    assert!(mgr.is_throttled(ConcurrencyCategory::Bash));
    assert_eq!(mgr.available_permits(ConcurrencyCategory::Bash), 0);
}

#[test]
fn concurrency_global_manager() {
    let mgr = global_concurrency_manager();
    assert!(mgr.limit(ConcurrencyCategory::Mcp) > 0);
}

// ---------------------------------------------------------------------------
// circuit_breaker
// ---------------------------------------------------------------------------

#[test]
fn circuit_state_variants() {
    assert_eq!(CircuitState::Closed, CircuitState::Closed);
    assert_ne!(CircuitState::Closed, CircuitState::Open);
    assert_ne!(CircuitState::HalfOpen, CircuitState::Open);
}

#[test]
fn circuit_level_parent() {
    assert_eq!(CircuitLevel::Tool.parent(), Some(CircuitLevel::Provider));
    assert_eq!(
        CircuitLevel::Provider.parent(),
        Some(CircuitLevel::Global)
    );
    assert_eq!(
        CircuitLevel::McpServer.parent(),
        Some(CircuitLevel::Global)
    );
    assert_eq!(CircuitLevel::Global.parent(), None);
}

#[test]
fn circuit_node_new_defaults() {
    let n = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
    assert_eq!(n.name, "test");
    assert_eq!(n.state, CircuitState::Closed);
    assert!(n.can_execute());
    assert!(n.is_healthy());
}

#[test]
fn circuit_node_failure_rate_empty() {
    let n = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
    assert!((n.failure_rate() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn circuit_node_failure_rate() {
    let mut n = CircuitNode::new("test", CircuitLevel::Tool, 10, Duration::from_secs(30));
    n.record_failure();
    n.record_failure();
    assert!((n.failure_rate() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn circuit_node_recovery_time_none_when_closed() {
    let n = CircuitNode::new("test", CircuitLevel::Tool, 3, Duration::from_secs(30));
    assert!(n.recovery_time_remaining().is_none());
}

#[test]
fn circuit_node_reset() {
    let mut n = CircuitNode::new("test", CircuitLevel::Tool, 2, Duration::from_millis(1));
    n.record_failure();
    n.record_failure();
    assert_eq!(n.state, CircuitState::Open);
    n.reset();
    assert_eq!(n.state, CircuitState::Closed);
    assert!(n.is_healthy());
}

#[test]
fn circuit_node_latency_percentiles() {
    let mut n = CircuitNode::new("test", CircuitLevel::Tool, 10, Duration::from_secs(30));
    for i in 1..=20 {
        n.record_success(i as f64);
    }
    assert!(n.latency_p50_ms > 0.0);
    assert!(n.latency_p95_ms >= n.latency_p50_ms);
    assert!(n.latency_p99_ms >= n.latency_p95_ms);
}

#[test]
fn circuit_node_open_count() {
    let mut n = CircuitNode::new("test", CircuitLevel::Tool, 2, Duration::from_millis(1));
    n.record_failure();
    n.record_failure();
    assert_eq!(n.state, CircuitState::Open);
    std::thread::sleep(Duration::from_millis(2));
    n.record_success(10.0);
    n.record_success(10.0);
    assert_eq!(n.state, CircuitState::Closed);
    n.record_failure();
    n.record_failure();
    assert_eq!(n.state, CircuitState::Open);
}

#[test]
fn circuit_forest_new() {
    let f = CircuitForest::new();
    assert!(f.get("unknown").is_none());
    assert!(f.is_healthy("unknown"));
}

#[test]
fn circuit_forest_register_and_get() {
    let mut f = CircuitForest::new();
    f.register("p1", CircuitLevel::Provider, 5, Duration::from_secs(30));
    assert!(f.get("p1").is_some());
    assert!(f.is_healthy("p1"));
}

#[test]
fn circuit_forest_open_circuits() {
    let mut f = CircuitForest::new();
    f.register("p1", CircuitLevel::Provider, 1, Duration::from_secs(3600));
    f.record_failure("p1");
    let open = f.open_circuits();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].name, "p1");
}

#[test]
fn circuit_forest_degraded_providers() {
    let mut f = CircuitForest::new();
    f.register("p1", CircuitLevel::Provider, 1, Duration::from_secs(3600));
    f.register("p2", CircuitLevel::Provider, 5, Duration::from_secs(3600));
    f.record_failure("p1");
    let d = f.degraded_providers();
    assert!(d.contains(&"p1".to_string()));
    assert!(!d.contains(&"p2".to_string()));
}

#[test]
fn circuit_forest_reset() {
    let mut f = CircuitForest::new();
    f.register("p1", CircuitLevel::Provider, 1, Duration::from_secs(3600));
    f.record_failure("p1");
    assert!(!f.is_healthy("p1"));
    f.reset("p1");
    assert!(f.is_healthy("p1"));
}

#[test]
fn circuit_global_forest() {
    let f = global_circuit_forest();
    let g = f.lock().unwrap();
    assert!(g.get("global").is_some());
    assert!(g.get("mcp").is_some());
}

#[test]
fn circuit_forest_can_execute_unknown() {
    let f = CircuitForest::new();
    assert!(f.can_execute("nonexistent"));
}

// ---------------------------------------------------------------------------
// rate_limiter
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_bucket_new() {
    let b = AdaptiveTokenBucket::new("t", 100.0, 1.0, 200.0, 10.0);
    assert_eq!(b.name, "t");
    assert!((b.remaining() - 100.0).abs() < 0.01);
    assert!(!b.is_exhausted());
}

#[test]
fn rate_limiter_bucket_allow_and_consume() {
    let mut b = AdaptiveTokenBucket::new("t", 100.0, 1.0, 200.0, 10.0);
    assert!(b.allow(50.0));
    assert!((b.remaining() - 50.0).abs() < 0.01);
    assert!(b.try_consume(30.0).is_ok());
    assert!((b.remaining() - 20.0).abs() < 0.01);
    assert!(!b.allow(30.0));
}

#[test]
fn rate_limiter_bucket_exhausted() {
    let mut b = AdaptiveTokenBucket::new("t", 1.0, 0.01, 1.0, 1.0);
    b.allow(1.0);
    assert!(b.is_exhausted());
}

#[test]
fn rate_limiter_bucket_reset() {
    let mut b = AdaptiveTokenBucket::new("t", 100.0, 1.0, 200.0, 10.0);
    b.allow(50.0);
    b.record_error();
    b.reset();
    assert!((b.remaining() - 100.0).abs() < 0.01);
}

#[test]
fn rate_limiter_bucket_utilization() {
    let mut b = AdaptiveTokenBucket::new("t", 100.0, 1.0, 200.0, 10.0);
    assert!(b.utilization() > 0.99);
    b.allow(50.0);
    assert!(b.utilization() < 0.6);
}

#[test]
fn rate_limiter_bucket_refill() {
    let mut b = AdaptiveTokenBucket::new("t", 100.0, 50.0, 200.0, 10.0);
    b.allow(100.0);
    assert!((b.remaining()).abs() < 0.01);
    std::thread::sleep(Duration::from_millis(100));
    b.allow(0.0);
    assert!(b.remaining() > 0.0);
}

#[test]
fn rate_limiter_registry_new() {
    let r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    assert!(r.bucket_names().is_empty());
}

#[test]
fn rate_limiter_registry_register_and_allow() {
    let mut r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("p1");
    assert!(r.allow("p1", 10.0));
    assert_eq!(r.remaining("p1"), Some(50.0));
}

#[test]
fn rate_limiter_registry_unknown() {
    let mut r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    assert!(r.allow("unknown", 10.0));
}

#[test]
fn rate_limiter_registry_is_exhausted() {
    let mut r = TokenBucketRegistry::new(1.0, 0.01, 1.0, 1.0);
    r.register("p1");
    r.allow("p1", 1.0);
    assert!(r.is_exhausted("p1"));
}

#[test]
fn rate_limiter_registry_reset() {
    let mut r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("p1");
    r.allow("p1", 30.0);
    r.reset("p1");
    assert_eq!(r.remaining("p1"), Some(60.0));
}

#[test]
fn rate_limiter_registry_bucket_names() {
    let mut r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("a");
    r.register("b");
    let mut names = r.bucket_names();
    names.sort();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn rate_limiter_registry_iter() {
    let mut r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register("p1");
    let count = r.iter().count();
    assert_eq!(count, 1);
}

#[test]
fn rate_limiter_registry_global() {
    let r = global_rate_limiter();
    let mut g = r.lock().unwrap();
    assert!(g.get_mut("anthropic").is_some());
}

#[test]
fn rate_limiter_registry_register_with_params() {
    let mut r = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
    r.register_with_params("c", 200.0, 5.0, 500.0, 20.0);
    let b = r.get_mut("c").unwrap();
    assert_eq!(b.base_capacity, 200.0);
    assert_eq!(b.refill_rate, 5.0);
}

// ---------------------------------------------------------------------------
// green_contract
// ---------------------------------------------------------------------------

#[test]
fn green_level_as_str() {
    assert_eq!(GreenContractLevel::TargetedTests.as_str(), "targeted_tests");
    assert_eq!(GreenContractLevel::Package.as_str(), "package");
    assert_eq!(GreenContractLevel::Workspace.as_str(), "workspace");
    assert_eq!(GreenContractLevel::MergeReady.as_str(), "merge_ready");
}

#[test]
fn green_level_display() {
    assert_eq!(GreenContractLevel::TargetedTests.to_string(), "targeted_tests");
    assert_eq!(GreenContractLevel::MergeReady.to_string(), "merge_ready");
}

#[test]
fn green_level_ordering() {
    assert!(GreenContractLevel::TargetedTests < GreenContractLevel::Package);
    assert!(GreenContractLevel::Package < GreenContractLevel::Workspace);
    assert!(GreenContractLevel::Workspace < GreenContractLevel::MergeReady);
}

#[test]
fn green_level_serde_roundtrip() {
    let j = serde_json::to_string(&GreenContractLevel::Package).unwrap();
    let back: GreenContractLevel = serde_json::from_str(&j).unwrap();
    assert_eq!(back, GreenContractLevel::Package);
}

#[test]
fn green_contract_new() {
    let c = GreenContract::new(GreenContractLevel::Workspace);
    assert_eq!(c.required_level, GreenContractLevel::Workspace);
}

#[test]
fn green_contract_evaluate_satisfied() {
    let c = GreenContract::new(GreenContractLevel::Package);
    let o = c.evaluate(Some(GreenContractLevel::Workspace));
    assert!(o.is_satisfied());
}

#[test]
fn green_contract_evaluate_unsatisfied() {
    let c = GreenContract::new(GreenContractLevel::Workspace);
    let o = c.evaluate(Some(GreenContractLevel::Package));
    assert!(!o.is_satisfied());
}

#[test]
fn green_contract_evaluate_none() {
    let c = GreenContract::new(GreenContractLevel::MergeReady);
    let o = c.evaluate(None);
    assert!(!o.is_satisfied());
}

#[test]
fn green_contract_is_satisfied_by() {
    let c = GreenContract::new(GreenContractLevel::TargetedTests);
    assert!(c.is_satisfied_by(GreenContractLevel::MergeReady));
    assert!(c.is_satisfied_by(GreenContractLevel::TargetedTests));
}

#[test]
fn green_contract_outcome_serde_roundtrip() {
    let o = GreenContractOutcome::Satisfied {
        required_level: GreenContractLevel::Package,
        observed_level: GreenContractLevel::Workspace,
    };
    let j = serde_json::to_string(&o).unwrap();
    let back: GreenContractOutcome = serde_json::from_str(&j).unwrap();
    assert!(back.is_satisfied());
}

#[test]
fn green_contract_outcome_unsatisfied_serde() {
    let o = GreenContractOutcome::Unsatisfied {
        required_level: GreenContractLevel::MergeReady,
        observed_level: None,
    };
    let j = serde_json::to_string(&o).unwrap();
    let back: GreenContractOutcome = serde_json::from_str(&j).unwrap();
    assert!(!back.is_satisfied());
}

// ---------------------------------------------------------------------------
// forensic
// ---------------------------------------------------------------------------

#[test]
fn forensic_entry_new() {
    let e = ForensicEntry::new("test");
    assert_eq!(e.event_type, "test");
    assert!(e.data.is_empty());
    assert!(e.timestamp > 0);
}

#[test]
fn forensic_entry_with() {
    let e = ForensicEntry::new("cmd")
        .with("k1", "v1")
        .with("k2", "v2");
    assert_eq!(e.data.len(), 2);
    assert_eq!(e.data.get("k1").unwrap(), "v1");
}

#[test]
fn forensic_entry_with_cwd() {
    let e = ForensicEntry::new("env").with_cwd();
    assert!(e.data.contains_key("cwd"));
}

#[test]
fn forensic_entry_to_json() {
    let e = ForensicEntry::new("test").with("key", "val");
    let j = e.to_json();
    assert_eq!(j["event_type"], "test");
    assert_eq!(j["data"]["key"], "val");
    assert!(j["timestamp"].is_number());
}

#[test]
fn forensic_entry_capture_id_increments() {
    let e1 = ForensicEntry::new("a");
    let e2 = ForensicEntry::new("b");
    assert!(e2.capture_id > e1.capture_id);
}

#[test]
fn forensic_recorder_new() {
    let r = ForensicRecorder::new(100);
    assert!(!r.is_enabled());
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn forensic_recorder_enable_disable() {
    let mut r = ForensicRecorder::new(100);
    r.enable(std::path::PathBuf::from("/tmp/forensic_test"));
    assert!(r.is_enabled());
    r.disable();
    assert!(!r.is_enabled());
}

#[test]
fn forensic_recorder_disabled_no_record() {
    let mut r = ForensicRecorder::new(100);
    r.record(ForensicEntry::new("test"));
    assert!(r.is_empty());
}

#[test]
fn forensic_recorder_enabled_records() {
    let dir = std::env::temp_dir().join(format!("forensic-test-{}", std::process::id()));
    let mut r = ForensicRecorder::new(100);
    r.enable(dir.clone());
    r.record(ForensicEntry::new("test"));
    assert_eq!(r.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_max_entries() {
    let dir = std::env::temp_dir().join(format!("forensic-max-{}", std::process::id()));
    let mut r = ForensicRecorder::new(3);
    r.enable(dir.clone());
    for i in 0..5 {
        r.record(ForensicEntry::new(&format!("e{i}")));
    }
    assert_eq!(r.len(), 3);
    assert_eq!(r.entries()[0].event_type, "e2");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_export_json() {
    let dir = std::env::temp_dir().join(format!("forensic-export-{}", std::process::id()));
    let mut r = ForensicRecorder::new(100);
    r.enable(dir.clone());
    r.record(ForensicEntry::new("e1"));
    r.record(ForensicEntry::new("e2"));
    let j = r.export_json();
    assert_eq!(j.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_capture_environment() {
    let dir = std::env::temp_dir().join(format!("forensic-env-{}", std::process::id()));
    let mut r = ForensicRecorder::new(100);
    r.enable(dir.clone());
    r.capture_environment();
    assert_eq!(r.len(), 1);
    assert_eq!(r.entries()[0].event_type, "environment");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_capture_command() {
    let dir = std::env::temp_dir().join(format!("forensic-cmd-{}", std::process::id()));
    let mut r = ForensicRecorder::new(100);
    r.enable(dir.clone());
    r.capture_command("bash", &["-c".into(), "echo hi".into()]);
    assert_eq!(r.len(), 1);
    assert_eq!(r.entries()[0].event_type, "command");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_capture_file_ops() {
    let dir = std::env::temp_dir().join(format!("forensic-file-{}", std::process::id()));
    let mut r = ForensicRecorder::new(100);
    r.enable(dir.clone());
    r.capture_file_read("/etc/passwd");
    r.capture_file_write("/tmp/test.txt", 1024);
    assert_eq!(r.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_recorder_capture_network() {
    let dir = std::env::temp_dir().join(format!("forensic-net-{}", std::process::id()));
    let mut r = ForensicRecorder::new(100);
    r.enable(dir.clone());
    r.capture_network("https://example.com", "POST");
    assert_eq!(r.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forensic_global() {
    let f = global_forensic();
    let g = f.lock().unwrap();
    assert!(!g.is_enabled());
}

// ---------------------------------------------------------------------------
// health_probe
// ---------------------------------------------------------------------------

#[test]
fn health_probe_status_default() {
    assert_eq!(HealthStatus::default(), HealthStatus::Unknown);
}

#[test]
fn health_probe_status_equality() {
    assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
    assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
    assert_ne!(HealthStatus::Degraded, HealthStatus::Unknown);
}

#[test]
fn latency_window_new() {
    let w = LatencyWindow::new(10);
    assert!(w.is_empty());
    assert_eq!(w.len(), 0);
}

#[test]
fn latency_window_record_and_stats() {
    let mut w = LatencyWindow::new(10);
    w.record(10.0);
    w.record(20.0);
    w.record(30.0);
    assert_eq!(w.len(), 3);
    assert!(!w.is_empty());
    assert!(w.p50().is_some());
    assert!(w.p95().is_some());
    assert!(w.p99().is_some());
    assert!(w.average().is_some());
    assert!(w.max().is_some());
}

#[test]
fn latency_window_max_capacity() {
    let mut w = LatencyWindow::new(3);
    w.record(1.0);
    w.record(2.0);
    w.record(3.0);
    w.record(4.0);
    assert_eq!(w.len(), 3);
    assert_eq!(w.max(), Some(4.0));
}

#[test]
fn latency_window_clear() {
    let mut w = LatencyWindow::new(10);
    w.record(1.0);
    w.record(2.0);
    w.clear();
    assert!(w.is_empty());
}

#[test]
fn latency_window_empty_stats() {
    let w = LatencyWindow::new(10);
    assert!(w.p50().is_none());
    assert!(w.p95().is_none());
    assert!(w.p99().is_none());
    assert!(w.average().is_none());
    assert!(w.max().is_none());
}

#[test]
fn probe_target_new() {
    let t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    assert_eq!(t.name, "p");
    assert_eq!(t.status, HealthStatus::Unknown);
    assert!(t.due_for_probe());
    assert!(t.is_available());
    assert_eq!(t.error_rate(), 0.0);
}

#[test]
fn probe_target_success_healthy() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    t.record_success(100.0);
    t.record_success(100.0);
    t.record_success(100.0);
    assert_eq!(t.status, HealthStatus::Healthy);
    assert_eq!(t.consecutive_successes, 3);
}

#[test]
fn probe_target_latency_degraded() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 500.0);
    t.record_success(600.0);
    assert_eq!(t.status, HealthStatus::Degraded);
}

#[test]
fn probe_target_failure_unhealthy() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    for _ in 0..5 {
        t.record_failure(100.0);
    }
    assert_eq!(t.status, HealthStatus::Unhealthy);
    assert!(!t.is_available());
}

#[test]
fn probe_target_failure_degraded() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    t.record_failure(100.0);
    assert_eq!(t.status, HealthStatus::Unknown);
    t.record_failure(100.0);
    assert_eq!(t.status, HealthStatus::Degraded);
}

#[test]
fn probe_target_error_rate() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    t.record_success(100.0);
    t.record_failure(100.0);
    assert!((t.error_rate() - 0.5).abs() < 0.001);
}

#[test]
fn probe_target_report() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    t.record_success(100.0);
    t.record_success(100.0);
    t.record_success(100.0);
    let r = t.report();
    assert!(r.is_healthy());
    assert_eq!(r.total_probes, 3);
}

#[test]
fn probe_report_should_degrade() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    for _ in 0..10 {
        t.record_success(6000.0);
    }
    assert!(t.report().should_degrade());
}

#[test]
fn probe_report_should_open_circuit() {
    let mut t = ProbeTarget::new("p", Duration::from_secs(5), 10000.0);
    for _ in 0..6 {
        t.record_failure(12000.0);
    }
    assert!(t.report().should_open_circuit());
}

#[test]
fn health_probe_registry_new() {
    let r = HealthProbeRegistry::new();
    assert!(r.get("unknown").is_none());
}

#[test]
fn health_probe_registry_register_and_get() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    assert!(r.get("p1").is_some());
}

#[test]
fn health_probe_registry_record_success() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    r.record_success("p1", 100.0);
    assert_eq!(r.get("p1").unwrap().total_probes, 1);
}

#[test]
fn health_probe_registry_record_failure() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    r.record_failure("p1", 1000.0);
    assert_eq!(r.get("p1").unwrap().failed_probes, 1);
}

#[test]
fn health_probe_registry_due_targets() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    let due = r.due_targets();
    assert!(due.contains(&"p1".to_string()));
}

#[test]
fn health_probe_registry_reports() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    r.record_success("p1", 100.0);
    let reports = r.reports();
    assert_eq!(reports.len(), 1);
}

#[test]
fn health_probe_registry_report_for() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    assert!(r.report_for("p1").is_some());
    assert!(r.report_for("missing").is_none());
}

#[test]
fn health_probe_registry_unhealthy() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    for _ in 0..5 {
        r.record_failure("p1", 100.0);
    }
    let u = r.unhealthy_targets();
    assert!(u.contains(&"p1".to_string()));
}

#[test]
fn health_probe_registry_degraded() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    r.record_failure("p1", 100.0);
    r.record_failure("p1", 100.0);
    let d = r.degraded_targets();
    assert!(d.contains(&"p1".to_string()));
}

#[test]
fn health_probe_registry_remove() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    r.remove("p1");
    assert!(r.get("p1").is_none());
}

#[test]
fn health_probe_registry_iter() {
    let mut r = HealthProbeRegistry::new();
    r.register(ProbeTarget::new("p1", Duration::from_secs(5), 10000.0));
    r.register(ProbeTarget::new("p2", Duration::from_secs(5), 10000.0));
    let count = r.iter().count();
    assert_eq!(count, 2);
}

#[test]
fn health_probe_global_registry() {
    let r = global_health_registry();
    let g = r.lock().unwrap();
    assert!(g.get("anthropic").is_some());
}

// ---------------------------------------------------------------------------
// recovery_recipes
// ---------------------------------------------------------------------------

#[test]
fn recovery_all_scenarios_count() {
    assert_eq!(FailureScenario::all().len(), 7);
}

#[test]
fn recovery_scenario_display() {
    assert_eq!(
        FailureScenario::TrustPromptUnresolved.to_string(),
        "trust_prompt_unresolved"
    );
    assert_eq!(
        FailureScenario::McpHandshakeFailure.to_string(),
        "mcp_handshake_failure"
    );
}

#[test]
fn recovery_scenario_serde_roundtrip() {
    let j = serde_json::to_string(&FailureScenario::StaleBranch).unwrap();
    let back: FailureScenario = serde_json::from_str(&j).unwrap();
    assert_eq!(back, FailureScenario::StaleBranch);
}

#[test]
fn recovery_context_new() {
    let ctx = RecoveryContext::new();
    assert_eq!(
        ctx.attempt_count(&FailureScenario::StaleBranch),
        0
    );
    assert!(ctx.events().is_empty());
}

#[test]
fn recovery_context_with_fail_at_step() {
    let ctx = RecoveryContext::new().with_fail_at_step(2);
    assert!(ctx.events().is_empty());
}

#[test]
fn recovery_recipe_for_each_scenario() {
    for scenario in FailureScenario::all() {
        let recipe = recipe_for(scenario);
        assert_eq!(recipe.scenario, *scenario);
        assert!(!recipe.steps.is_empty());
    }
}

#[test]
fn recovery_recipe_stale_branch_steps() {
    let r = recipe_for(&FailureScenario::StaleBranch);
    assert_eq!(r.steps.len(), 2);
    assert_eq!(r.steps[0], RecoveryStep::RebaseBranch);
    assert_eq!(r.steps[1], RecoveryStep::CleanBuild);
}

#[test]
fn recovery_recipe_mcp_handshake_policy() {
    let r = recipe_for(&FailureScenario::McpHandshakeFailure);
    assert_eq!(r.escalation_policy, EscalationPolicy::Abort);
}

#[test]
fn recovery_recipe_partial_plugin_policy() {
    let r = recipe_for(&FailureScenario::PartialPluginStartup);
    assert_eq!(r.escalation_policy, EscalationPolicy::LogAndContinue);
    assert_eq!(r.steps.len(), 2);
}

#[test]
fn recovery_attempt_success() {
    let mut ctx = RecoveryContext::new();
    let result = attempt_recovery(&FailureScenario::TrustPromptUnresolved, &mut ctx);
    assert!(matches!(result, RecoveryResult::Recovered { steps_taken: 1 }));
    assert_eq!(ctx.events().len(), 2);
}

#[test]
fn recovery_attempt_escalation() {
    let mut ctx = RecoveryContext::new();
    let _ = attempt_recovery(&FailureScenario::TrustPromptUnresolved, &mut ctx);
    let result = attempt_recovery(&FailureScenario::TrustPromptUnresolved, &mut ctx);
    assert!(matches!(result, RecoveryResult::EscalationRequired { .. }));
}

#[test]
fn recovery_attempt_partial_failure() {
    let mut ctx = RecoveryContext::new().with_fail_at_step(1);
    let result = attempt_recovery(&FailureScenario::PartialPluginStartup, &mut ctx);
    match result {
        RecoveryResult::PartialRecovery {
            recovered,
            remaining,
        } => {
            assert_eq!(recovered.len(), 1);
            assert_eq!(remaining.len(), 1);
        }
        _ => panic!("expected PartialRecovery"),
    }
}

#[test]
fn recovery_attempt_first_step_failure() {
    let mut ctx = RecoveryContext::new().with_fail_at_step(0);
    let result = attempt_recovery(&FailureScenario::CompileRedCrossCrate, &mut ctx);
    assert!(matches!(result, RecoveryResult::EscalationRequired { .. }));
}

#[test]
fn recovery_step_serde_roundtrip() {
    let step = RecoveryStep::RetryMcpHandshake { timeout: 5000 };
    let j = serde_json::to_string(&step).unwrap();
    let back: RecoveryStep = serde_json::from_str(&j).unwrap();
    assert_eq!(back, step);
}

#[test]
fn recovery_event_serde_roundtrip() {
    let e = RecoveryEvent::RecoverySucceeded;
    let j = serde_json::to_string(&e).unwrap();
    let back: RecoveryEvent = serde_json::from_str(&j).unwrap();
    assert_eq!(back, RecoveryEvent::RecoverySucceeded);
}

#[test]
fn recovery_context_tracks_attempts() {
    let mut ctx = RecoveryContext::new();
    attempt_recovery(&FailureScenario::StaleBranch, &mut ctx);
    assert_eq!(ctx.attempt_count(&FailureScenario::StaleBranch), 1);
    assert_eq!(ctx.attempt_count(&FailureScenario::PromptMisdelivery), 0);
}

// ---------------------------------------------------------------------------
// size_budget
// ---------------------------------------------------------------------------

#[test]
fn size_budget_tool_kind_from_name() {
    assert_eq!(ToolKind::from_name("read_file"), ToolKind::Read);
    assert_eq!(ToolKind::from_name("Read"), ToolKind::Read);
    assert_eq!(ToolKind::from_name("write_file"), ToolKind::Write);
    assert_eq!(ToolKind::from_name("Write"), ToolKind::Write);
    assert_eq!(ToolKind::from_name("edit_file"), ToolKind::Edit);
    assert_eq!(ToolKind::from_name("Edit"), ToolKind::Edit);
    assert_eq!(ToolKind::from_name("glob_search"), ToolKind::Glob);
    assert_eq!(ToolKind::from_name("GlobSearch"), ToolKind::Glob);
    assert_eq!(ToolKind::from_name("glob"), ToolKind::Glob);
    assert_eq!(ToolKind::from_name("grep_search"), ToolKind::Grep);
    assert_eq!(ToolKind::from_name("GrepSearch"), ToolKind::Grep);
    assert_eq!(ToolKind::from_name("grep"), ToolKind::Grep);
    assert_eq!(ToolKind::from_name("bash"), ToolKind::Bash);
    assert_eq!(ToolKind::from_name("Bash"), ToolKind::Bash);
    assert_eq!(ToolKind::from_name("other"), ToolKind::Other);
}

#[test]
fn size_budget_tool_kind_equality() {
    assert_eq!(ToolKind::Read, ToolKind::Read);
    assert_ne!(ToolKind::Read, ToolKind::Write);
}

#[test]
fn size_budget_tool_kind_hash() {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    m.insert(ToolKind::Read, 1);
    m.insert(ToolKind::Write, 2);
    assert_eq!(m.len(), 2);
}

#[test]
fn size_budget_tool_budget_for_read() {
    let b = ToolBudget::for_read();
    assert_eq!(b.max_bytes, 10 * 1024 * 1024);
    assert_eq!(b.max_calls, 200);
}

#[test]
fn size_budget_tool_budget_for_write() {
    let b = ToolBudget::for_write();
    assert_eq!(b.max_bytes, 5 * 1024 * 1024);
    assert_eq!(b.max_calls, 100);
}

#[test]
fn size_budget_tool_budget_for_glob() {
    let b = ToolBudget::for_glob();
    assert_eq!(b.max_entries, Some(1000));
    assert_eq!(b.max_calls, 50);
}

#[test]
fn size_budget_tool_budget_for_grep() {
    let b = ToolBudget::for_grep();
    assert_eq!(b.max_bytes, 1024 * 1024);
}

#[test]
fn size_budget_tool_budget_for_bash() {
    let b = ToolBudget::for_bash();
    assert_eq!(b.max_calls, 100);
}

#[test]
fn size_budget_tool_budget_for_edit() {
    let b = ToolBudget::for_edit();
    assert_eq!(b.max_bytes, 5 * 1024 * 1024);
}

#[test]
fn size_budget_size_budgeter_new() {
    let b = SizeBudgeter::new();
    let s = b.session_statistics();
    assert_eq!(s.total_calls, 0);
    assert_eq!(s.total_bytes, 0);
}

#[test]
fn size_budget_check_read_ok() {
    let mut b = SizeBudgeter::new();
    assert!(b.check_read(1024).is_ok());
    assert!(b.check_read(2048).is_ok());
}

#[test]
fn size_budget_check_write_ok() {
    let mut b = SizeBudgeter::new();
    assert!(b.check_write(1024).is_ok());
}

#[test]
fn size_budget_check_glob_ok() {
    let mut b = SizeBudgeter::new();
    assert!(b.check_glob(100).is_ok());
}

#[test]
fn size_budget_check_grep_ok() {
    let mut b = SizeBudgeter::new();
    assert!(b.check_grep(1024).is_ok());
}

#[test]
fn size_budget_check_bash_ok() {
    let mut b = SizeBudgeter::new();
    assert!(b.check_bash().is_ok());
}

#[test]
fn size_budget_statistics_tracked() {
    let mut b = SizeBudgeter::new();
    b.check_read(100).unwrap();
    b.check_write(200).unwrap();
    let s = b.session_statistics();
    assert_eq!(s.total_calls, 2);
    assert_eq!(s.total_bytes, 300);
}

#[test]
fn size_budget_session_stats_serde_roundtrip() {
    let s = SessionStats {
        total_calls: 42,
        total_bytes: 999,
    };
    let j = serde_json::to_string(&s).unwrap();
    let back: SessionStats = serde_json::from_str(&j).unwrap();
    assert_eq!(back.total_calls, 42);
}

#[test]
fn size_budget_exceeded_display() {
    let e = BudgetExceeded::SessionCalls(5001);
    assert!(e.to_string().contains("5001"));

    let e = BudgetExceeded::SessionBytes(200 * 1024 * 1024 + 1);
    assert!(e.to_string().contains("200MB"));

    let e = BudgetExceeded::ToolCalls {
        tool: ToolKind::Read,
        count: 201,
        limit: 200,
    };
    assert!(e.to_string().contains("201"));

    let e = BudgetExceeded::ToolBytes {
        tool: ToolKind::Write,
        bytes: 6_000_000,
        limit: 5_000_000,
    };
    assert!(e.to_string().contains("6000000"));
}

#[test]
fn size_budget_exceeded_is_error() {
    let e = BudgetExceeded::SessionCalls(5001);
    let _: &dyn std::error::Error = &e;
}

#[test]
fn size_budget_read_exceeds_calls() {
    let mut b = SizeBudgeter::new();
    for _ in 0..200 {
        b.check_read(1).unwrap();
    }
    assert!(b.check_read(1).is_err());
}

// ---------------------------------------------------------------------------
// provider_chain
// ---------------------------------------------------------------------------

#[test]
fn provider_state_can_serve() {
    assert!(ProviderState::Available.can_serve());
    assert!(ProviderState::Degraded.can_serve());
    assert!(!ProviderState::Unavailable.can_serve());
}

#[test]
fn provider_state_equality() {
    assert_eq!(ProviderState::Available, ProviderState::Available);
    assert_ne!(ProviderState::Available, ProviderState::Unavailable);
}

#[test]
fn provider_chain_new() {
    let c = ProviderChain::new(Some("p".into()), vec!["f1".into()]);
    assert_eq!(c.best_available(), Some("p".into()));
}

#[test]
fn provider_chain_no_primary() {
    let c = ProviderChain::new(None, vec!["f1".into()]);
    assert_eq!(c.best_available(), Some("f1".into()));
}

#[test]
fn provider_chain_empty() {
    let c = ProviderChain::new(None, vec![]);
    assert!(c.best_available().is_none());
}

#[test]
fn provider_chain_next_after() {
    let c = ProviderChain::new(
        Some("p".into()),
        vec!["f1".into(), "f2".into()],
    );
    assert_eq!(c.next_after("p"), Some("f1".into()));
    assert_eq!(c.next_after("f1"), Some("f2".into()));
}

#[test]
fn provider_chain_next_after_unknown() {
    let c = ProviderChain::new(Some("p".into()), vec![]);
    assert_eq!(c.next_after("unknown"), Some("p".into()));
}

#[test]
fn provider_chain_all_available() {
    let c = ProviderChain::new(
        Some("p".into()),
        vec!["f1".into()],
    );
    assert_eq!(c.all_available().len(), 2);
}

#[test]
fn provider_chain_status() {
    let c = ProviderChain::new(Some("p".into()), vec!["f1".into()]);
    let s = c.status();
    assert_eq!(s.len(), 2);
}

#[test]
fn provider_chain_status_serde_roundtrip() {
    let s = ProviderChainStatus {
        provider: "p".into(),
        state: ProviderState::Available,
        circuit_ok: true,
        health_status: HealthStatus::Healthy,
        recovery_time_remaining_ms: None,
    };
    let j = serde_json::to_string(&s).unwrap();
    let back: ProviderChainStatus = serde_json::from_str(&j).unwrap();
    assert_eq!(back.provider, "p");
}

// ---------------------------------------------------------------------------
// siem_export
// ---------------------------------------------------------------------------

#[test]
fn siem_format_from_str() {
    assert_eq!(SiemFormat::from_str("ecs"), Some(SiemFormat::Ecs));
    assert_eq!(
        SiemFormat::from_str("splunk"),
        Some(SiemFormat::SplunkHec)
    );
    assert_eq!(
        SiemFormat::from_str("splunk-hec"),
        Some(SiemFormat::SplunkHec)
    );
    assert_eq!(
        SiemFormat::from_str("otel"),
        Some(SiemFormat::OpenTelemetry)
    );
    assert_eq!(
        SiemFormat::from_str("opentelemetry"),
        Some(SiemFormat::OpenTelemetry)
    );
    assert_eq!(SiemFormat::from_str("json"), Some(SiemFormat::Json));
    assert_eq!(SiemFormat::from_str("unknown"), None);
}

#[test]
fn siem_format_extensions() {
    assert_eq!(SiemFormat::Ecs.extensions(), "ecs.json");
    assert_eq!(SiemFormat::SplunkHec.extensions(), "splunk.json");
    assert_eq!(SiemFormat::OpenTelemetry.extensions(), "otel.json");
    assert_eq!(SiemFormat::Json.extensions(), "json");
}

#[test]
fn siem_format_content_type() {
    assert_eq!(SiemFormat::Ecs.content_type(), "application/ecs+json");
    assert_eq!(
        SiemFormat::SplunkHec.content_type(),
        "application/x-splunk-json"
    );
    assert_eq!(
        SiemFormat::OpenTelemetry.content_type(),
        "application/json"
    );
    assert_eq!(SiemFormat::Json.content_type(), "application/json");
}

#[test]
fn siem_format_equality() {
    assert_eq!(SiemFormat::Ecs, SiemFormat::Ecs);
    assert_ne!(SiemFormat::Ecs, SiemFormat::Json);
}

#[test]
fn siem_exporter_new() {
    let e = SiemExporter::new(SiemFormat::Json);
    assert!(e.export_string(&security::audit::AuditLog::new()).is_ok());
}

#[test]
fn siem_exporter_with_output_dir() {
    let e = SiemExporter::new(SiemFormat::Json).with_output_dir("/tmp/test-siem");
    assert!(e.export_string(&security::audit::AuditLog::new()).is_ok());
}

#[test]
fn siem_exporter_pretty() {
    let e = SiemExporter::new(SiemFormat::Json).with_pretty(true);
    let s = e.export_string(&security::audit::AuditLog::new()).unwrap();
    assert!(s.contains('\n'));
}

#[test]
fn siem_export_result_serde() {
    let r = ExportResult {
        path: None,
        size: 100,
        format: SiemFormat::Json,
        entry_count: 5,
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: ExportResult = serde_json::from_str(&j).unwrap();
    assert_eq!(back.size, 100);
}

#[test]
fn siem_export_error_display() {
    let e = ExportError::Serialize("msg".into());
    assert!(e.to_string().contains("msg"));
    let e = ExportError::Io("io err".into());
    assert!(e.to_string().contains("io err"));
}

#[test]
fn siem_export_to_file() {
    let log = security::audit::AuditLog::new();
    let dir = std::env::temp_dir().join(format!("siem-test-{}", std::process::id()));
    let e = SiemExporter::new(SiemFormat::Json).with_output_dir(dir.to_str().unwrap());
    let r = e.export(&log, "test").unwrap();
    assert!(r.path.is_some());
    assert!(std::path::Path::new(r.path.as_ref().unwrap()).exists());
    let _ = std::fs::remove_file(r.path.unwrap());
    let _ = std::fs::remove_dir(&dir);
}

// ---------------------------------------------------------------------------
// plugin_lifecycle
// ---------------------------------------------------------------------------

#[test]
fn plugin_server_status_display() {
    assert_eq!(ServerStatus::Healthy.to_string(), "healthy");
    assert_eq!(ServerStatus::Degraded.to_string(), "degraded");
    assert_eq!(ServerStatus::Failed.to_string(), "failed");
}

#[test]
fn plugin_server_status_equality() {
    assert_eq!(ServerStatus::Healthy, ServerStatus::Healthy);
    assert_ne!(ServerStatus::Healthy, ServerStatus::Failed);
}

#[test]
fn plugin_server_status_serde_roundtrip() {
    let j = serde_json::to_string(&ServerStatus::Degraded).unwrap();
    let back: ServerStatus = serde_json::from_str(&j).unwrap();
    assert_eq!(back, ServerStatus::Degraded);
}

#[test]
fn plugin_state_display() {
    assert_eq!(PluginState::Unconfigured.to_string(), "unconfigured");
    assert_eq!(PluginState::Validated.to_string(), "validated");
    assert_eq!(PluginState::Starting.to_string(), "starting");
    assert_eq!(PluginState::Healthy.to_string(), "healthy");
    assert_eq!(PluginState::Degraded {
        healthy_servers: vec![],
        failed_servers: vec![],
    }
    .to_string(), "degraded");
    assert_eq!(PluginState::Failed { reason: "x".into() }.to_string(), "failed");
    assert_eq!(PluginState::ShuttingDown.to_string(), "shutting_down");
    assert_eq!(PluginState::Stopped.to_string(), "stopped");
}

#[test]
fn plugin_state_from_servers_empty() {
    let s = PluginState::from_servers(&[]);
    match s {
        PluginState::Failed { reason } => assert!(reason.contains("no servers")),
        _ => panic!("expected Failed"),
    }
}

#[test]
fn plugin_state_from_servers_all_healthy() {
    let servers = vec![
        ServerHealth {
            server_name: "a".into(),
            status: ServerStatus::Healthy,
            capabilities: vec![],
            last_error: None,
        },
        ServerHealth {
            server_name: "b".into(),
            status: ServerStatus::Healthy,
            capabilities: vec![],
            last_error: None,
        },
    ];
    assert_eq!(PluginState::from_servers(&servers), PluginState::Healthy);
}

#[test]
fn plugin_state_from_servers_all_failed() {
    let servers = vec![
        ServerHealth {
            server_name: "a".into(),
            status: ServerStatus::Failed,
            capabilities: vec![],
            last_error: None,
        },
    ];
    match PluginState::from_servers(&servers) {
        PluginState::Failed { reason } => assert!(reason.contains("1 servers failed")),
        _ => panic!("expected Failed"),
    }
}

#[test]
fn plugin_state_from_servers_degraded() {
    let servers = vec![
        ServerHealth {
            server_name: "a".into(),
            status: ServerStatus::Healthy,
            capabilities: vec![],
            last_error: None,
        },
        ServerHealth {
            server_name: "b".into(),
            status: ServerStatus::Failed,
            capabilities: vec![],
            last_error: None,
        },
    ];
    match PluginState::from_servers(&servers) {
        PluginState::Degraded {
            healthy_servers,
            failed_servers,
        } => {
            assert_eq!(healthy_servers, vec!["a".to_string()]);
            assert_eq!(failed_servers.len(), 1);
        }
        _ => panic!("expected Degraded"),
    }
}

#[test]
fn plugin_state_from_servers_degraded_keeps_degraded_server_usable() {
    let servers = vec![
        ServerHealth {
            server_name: "a".into(),
            status: ServerStatus::Degraded,
            capabilities: vec![],
            last_error: None,
        },
    ];
    match PluginState::from_servers(&servers) {
        PluginState::Degraded {
            healthy_servers,
            failed_servers,
        } => {
            assert_eq!(healthy_servers, vec!["a".to_string()]);
            assert!(failed_servers.is_empty());
        }
        _ => panic!("expected Degraded"),
    }
}

#[test]
fn plugin_state_serde_roundtrip() {
    let s = PluginState::Healthy;
    let j = serde_json::to_string(&s).unwrap();
    let back: PluginState = serde_json::from_str(&j).unwrap();
    assert_eq!(back, PluginState::Healthy);
}

#[test]
fn plugin_lifecycle_event_display() {
    assert_eq!(PluginLifecycleEvent::ConfigValidated.to_string(), "config_validated");
    assert_eq!(PluginLifecycleEvent::StartupHealthy.to_string(), "startup_healthy");
    assert_eq!(PluginLifecycleEvent::StartupDegraded.to_string(), "startup_degraded");
    assert_eq!(PluginLifecycleEvent::StartupFailed.to_string(), "startup_failed");
    assert_eq!(PluginLifecycleEvent::Shutdown.to_string(), "shutdown");
}

#[test]
fn plugin_degraded_mode_new() {
    let d = DegradedMode::new(
        vec!["t1".into()],
        vec!["t2".into()],
        "reason",
    );
    assert_eq!(d.available_tools, vec!["t1".to_string()]);
    assert_eq!(d.unavailable_tools, vec!["t2".to_string()]);
    assert_eq!(d.reason, "reason");
}

#[test]
fn plugin_healthcheck_new() {
    let h = PluginHealthcheck::new(
        "test",
        vec![ServerHealth {
            server_name: "s".into(),
            status: ServerStatus::Healthy,
            capabilities: vec![],
            last_error: None,
        }],
    );
    assert_eq!(h.plugin_name, "test");
    assert_eq!(h.state, PluginState::Healthy);
}

#[test]
fn plugin_healthcheck_degraded_mode_none_when_healthy() {
    let h = PluginHealthcheck::new(
        "test",
        vec![ServerHealth {
            server_name: "s".into(),
            status: ServerStatus::Healthy,
            capabilities: vec![],
            last_error: None,
        }],
    );
    let disc = DiscoveryResult {
        tools: vec![],
        resources: vec![],
        partial: false,
    };
    assert!(h.degraded_mode(&disc).is_none());
}

// ---------------------------------------------------------------------------
// mcp_server
// ---------------------------------------------------------------------------

#[test]
fn mcp_server_protocol_version() {
    assert_eq!(MCP_SERVER_PROTOCOL_VERSION, "2025-03-26");
}

// ---------------------------------------------------------------------------
// mcp_lifecycle_hardened
// ---------------------------------------------------------------------------

#[test]
fn mcp_lifecycle_phase_all() {
    assert_eq!(McpLifecyclePhase::all().len(), 11);
}

#[test]
fn mcp_lifecycle_phase_display() {
    assert_eq!(McpLifecyclePhase::ConfigLoad.to_string(), "config_load");
    assert_eq!(McpLifecyclePhase::Ready.to_string(), "ready");
    assert_eq!(McpLifecyclePhase::Cleanup.to_string(), "cleanup");
}

#[test]
fn mcp_lifecycle_phase_serde_roundtrip() {
    let j = serde_json::to_string(&McpLifecyclePhase::SpawnConnect).unwrap();
    let back: McpLifecyclePhase = serde_json::from_str(&j).unwrap();
    assert_eq!(back, McpLifecyclePhase::SpawnConnect);
}

#[test]
fn mcp_lifecycle_phase_ordering() {
    assert!(McpLifecyclePhase::ConfigLoad < McpLifecyclePhase::Ready);
}

#[test]
fn mcp_error_surface_new() {
    let e = McpErrorSurface::new(
        McpLifecyclePhase::SpawnConnect,
        Some("srv".into()),
        "err msg",
        Default::default(),
        true,
    );
    assert_eq!(e.phase, McpLifecyclePhase::SpawnConnect);
    assert_eq!(e.server_name.as_deref(), Some("srv"));
    assert!(e.recoverable);
    assert!(e.timestamp > 0);
}

#[test]
fn mcp_error_surface_display() {
    let e = McpErrorSurface::new(
        McpLifecyclePhase::SpawnConnect,
        Some("alpha".into()),
        "process exited",
        Default::default(),
        true,
    );
    let s = e.to_string();
    assert!(s.contains("spawn_connect"));
    assert!(s.contains("process exited"));
    assert!(s.contains("server: alpha"));
    assert!(s.contains("recoverable"));
}

#[test]
fn mcp_error_surface_is_error() {
    let e = McpErrorSurface::new(
        McpLifecyclePhase::Ready,
        None,
        "err",
        Default::default(),
        false,
    );
    let _: &dyn std::error::Error = &e;
}

#[test]
fn mcp_error_surface_serde_roundtrip() {
    let e = McpErrorSurface::new(
        McpLifecyclePhase::Ready,
        Some("s".into()),
        "msg",
        Default::default(),
        false,
    );
    let j = serde_json::to_string(&e).unwrap();
    let back: McpErrorSurface = serde_json::from_str(&j).unwrap();
    assert_eq!(back.phase, McpLifecyclePhase::Ready);
}

#[test]
fn mcp_phase_result_phase() {
    let r = McpPhaseResult::Success {
        phase: McpLifecyclePhase::Ready,
        duration: Duration::from_millis(10),
    };
    assert_eq!(r.phase(), McpLifecyclePhase::Ready);
}

#[test]
fn mcp_lifecycle_state_new() {
    let s = McpLifecycleState::new();
    assert!(s.current_phase().is_none());
    assert!(s.results().is_empty());
}

#[test]
fn mcp_lifecycle_validator_new() {
    let v = McpLifecycleValidator::new();
    assert!(v.state().current_phase().is_none());
}

#[test]
fn mcp_lifecycle_validator_valid_transitions() {
    assert!(McpLifecycleValidator::validate_phase_transition(
        McpLifecyclePhase::ConfigLoad,
        McpLifecyclePhase::ServerRegistration,
    ));
    assert!(McpLifecycleValidator::validate_phase_transition(
        McpLifecyclePhase::ToolDiscovery,
        McpLifecyclePhase::Ready,
    ));
    assert!(McpLifecycleValidator::validate_phase_transition(
        McpLifecyclePhase::Ready,
        McpLifecyclePhase::Invocation,
    ));
    assert!(McpLifecycleValidator::validate_phase_transition(
        McpLifecyclePhase::Invocation,
        McpLifecyclePhase::Ready,
    ));
}

#[test]
fn mcp_lifecycle_validator_invalid_transitions() {
    assert!(!McpLifecycleValidator::validate_phase_transition(
        McpLifecyclePhase::Ready,
        McpLifecyclePhase::ConfigLoad,
    ));
    assert!(!McpLifecycleValidator::validate_phase_transition(
        McpLifecyclePhase::Cleanup,
        McpLifecyclePhase::Ready,
    ));
}

#[test]
fn mcp_lifecycle_validator_run_full_lifecycle() {
    let mut v = McpLifecycleValidator::new();
    let phases = [
        McpLifecyclePhase::ConfigLoad,
        McpLifecyclePhase::ServerRegistration,
        McpLifecyclePhase::SpawnConnect,
        McpLifecyclePhase::InitializeHandshake,
        McpLifecyclePhase::ToolDiscovery,
        McpLifecyclePhase::Ready,
        McpLifecyclePhase::Invocation,
        McpLifecyclePhase::Ready,
        McpLifecyclePhase::Shutdown,
        McpLifecyclePhase::Cleanup,
    ];
    for phase in phases {
        let r = v.run_phase(phase);
        assert!(matches!(r, McpPhaseResult::Success { .. }));
    }
}

#[test]
fn mcp_lifecycle_validator_invalid_transition_records_failure() {
    let mut v = McpLifecycleValidator::new();
    let _ = v.run_phase(McpLifecyclePhase::ConfigLoad);
    let _ = v.run_phase(McpLifecyclePhase::ServerRegistration);
    let r = v.run_phase(McpLifecyclePhase::Ready);
    assert!(matches!(r, McpPhaseResult::Failure { .. }));
}

#[test]
fn mcp_lifecycle_validator_record_timeout() {
    let mut v = McpLifecycleValidator::new();
    let r = v.record_timeout(
        McpLifecyclePhase::SpawnConnect,
        Duration::from_millis(250),
        Some("srv".into()),
        Default::default(),
    );
    match r {
        McpPhaseResult::Timeout {
            phase,
            waited,
            error,
        } => {
            assert_eq!(phase, McpLifecyclePhase::SpawnConnect);
            assert_eq!(waited, Duration::from_millis(250));
            assert!(error.recoverable);
        }
        _ => panic!("expected Timeout"),
    }
}

#[test]
fn mcp_degraded_report_new() {
    let report = McpDegradedReport::new(
        vec!["a".into(), "a".into()],
        vec![],
        vec!["t1".into(), "t1".into()],
        vec!["t1".into(), "t2".into()],
    );
    assert_eq!(report.working_servers, vec!["a".to_string()]);
    assert_eq!(report.available_tools, vec!["t1".to_string()]);
    assert_eq!(report.missing_tools, vec!["t2".to_string()]);
}

#[test]
fn mcp_failed_server_serde_roundtrip() {
    let f = McpFailedServer {
        server_name: "s".into(),
        phase: McpLifecyclePhase::Ready,
        error: McpErrorSurface::new(
            McpLifecyclePhase::Ready,
            None,
            "err",
            Default::default(),
            false,
        ),
    };
    let j = serde_json::to_string(&f).unwrap();
    let back: McpFailedServer = serde_json::from_str(&j).unwrap();
    assert_eq!(back.server_name, "s");
}

// ---------------------------------------------------------------------------
// mcp_tool_bridge
// ---------------------------------------------------------------------------

#[test]
fn mcp_connection_status_display() {
    assert_eq!(McpConnectionStatus::Disconnected.to_string(), "disconnected");
    assert_eq!(McpConnectionStatus::Connecting.to_string(), "connecting");
    assert_eq!(McpConnectionStatus::Connected.to_string(), "connected");
    assert_eq!(McpConnectionStatus::AuthRequired.to_string(), "auth_required");
    assert_eq!(McpConnectionStatus::Error.to_string(), "error");
}

#[test]
fn mcp_connection_status_equality() {
    assert_eq!(McpConnectionStatus::Connected, McpConnectionStatus::Connected);
    assert_ne!(
        McpConnectionStatus::Connected,
        McpConnectionStatus::Disconnected
    );
}

#[test]
fn mcp_connection_status_serde_roundtrip() {
    let j = serde_json::to_string(&McpConnectionStatus::AuthRequired).unwrap();
    let back: McpConnectionStatus = serde_json::from_str(&j).unwrap();
    assert_eq!(back, McpConnectionStatus::AuthRequired);
}

#[test]
fn mcp_resource_info_serde_roundtrip() {
    let r = McpResourceInfo {
        uri: "res://data".into(),
        name: "Data".into(),
        description: Some("desc".into()),
        mime_type: Some("application/json".into()),
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: McpResourceInfo = serde_json::from_str(&j).unwrap();
    assert_eq!(back.uri, "res://data");
}

#[test]
fn mcp_tool_info_serde_roundtrip() {
    let t = McpToolInfo {
        name: "echo".into(),
        description: Some("Echo tool".into()),
        input_schema: Some(serde_json::json!({"type": "object"})),
    };
    let j = serde_json::to_string(&t).unwrap();
    let back: McpToolInfo = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, "echo");
}

#[test]
fn mcp_tool_registry_new() {
    let r = McpToolRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn mcp_tool_registry_register_and_get() {
    let r = McpToolRegistry::new();
    r.register_server(
        "srv",
        McpConnectionStatus::Connected,
        vec![],
        vec![],
        None,
    );
    assert!(r.get_server("srv").is_some());
    assert_eq!(r.len(), 1);
}

#[test]
fn mcp_tool_registry_get_missing() {
    let r = McpToolRegistry::new();
    assert!(r.get_server("missing").is_none());
}

#[test]
fn mcp_tool_registry_list_servers() {
    let r = McpToolRegistry::new();
    r.register_server("a", McpConnectionStatus::Connected, vec![], vec![], None);
    r.register_server("b", McpConnectionStatus::Connecting, vec![], vec![], None);
    assert_eq!(r.list_servers().len(), 2);
}

#[test]
fn mcp_tool_registry_upsert() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::Connecting, vec![], vec![], None);
    r.register_server(
        "s",
        McpConnectionStatus::Connected,
        vec![McpToolInfo {
            name: "t".into(),
            description: None,
            input_schema: None,
        }],
        vec![],
        Some("v1".into()),
    );
    let state = r.get_server("s").unwrap();
    assert_eq!(state.status, McpConnectionStatus::Connected);
    assert_eq!(state.tools.len(), 1);
    assert_eq!(state.server_info.as_deref(), Some("v1"));
}

#[test]
fn mcp_tool_registry_disconnect() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::Connected, vec![], vec![], None);
    assert!(r.disconnect("s").is_some());
    assert!(r.is_empty());
}

#[test]
fn mcp_tool_registry_disconnect_missing() {
    let r = McpToolRegistry::new();
    assert!(r.disconnect("missing").is_none());
}

#[test]
fn mcp_tool_registry_set_auth_status() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::AuthRequired, vec![], vec![], None);
    r.set_auth_status("s", McpConnectionStatus::Connected).unwrap();
    assert_eq!(
        r.get_server("s").unwrap().status,
        McpConnectionStatus::Connected
    );
}

#[test]
fn mcp_tool_registry_set_auth_status_missing() {
    let r = McpToolRegistry::new();
    assert!(r.set_auth_status("missing", McpConnectionStatus::Connected).is_err());
}

#[test]
fn mcp_tool_registry_list_tools_connected() {
    let r = McpToolRegistry::new();
    r.register_server(
        "s",
        McpConnectionStatus::Connected,
        vec![McpToolInfo {
            name: "t".into(),
            description: None,
            input_schema: None,
        }],
        vec![],
        None,
    );
    let tools = r.list_tools("s").unwrap();
    assert_eq!(tools.len(), 1);
}

#[test]
fn mcp_tool_registry_list_tools_disconnected() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::Disconnected, vec![], vec![], None);
    assert!(r.list_tools("s").is_err());
}

#[test]
fn mcp_tool_registry_list_tools_missing() {
    let r = McpToolRegistry::new();
    assert!(r.list_tools("missing").is_err());
}

#[test]
fn mcp_tool_registry_list_resources_connected() {
    let r = McpToolRegistry::new();
    r.register_server(
        "s",
        McpConnectionStatus::Connected,
        vec![],
        vec![McpResourceInfo {
            uri: "r://1".into(),
            name: "R".into(),
            description: None,
            mime_type: None,
        }],
        None,
    );
    let res = r.list_resources("s").unwrap();
    assert_eq!(res.len(), 1);
}

#[test]
fn mcp_tool_registry_list_resources_disconnected() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::Disconnected, vec![], vec![], None);
    assert!(r.list_resources("s").is_err());
}

#[test]
fn mcp_tool_registry_list_resources_missing() {
    let r = McpToolRegistry::new();
    assert!(r.list_resources("missing").is_err());
}

#[test]
fn mcp_tool_registry_read_resource() {
    let r = McpToolRegistry::new();
    r.register_server(
        "s",
        McpConnectionStatus::Connected,
        vec![],
        vec![McpResourceInfo {
            uri: "r://1".into(),
            name: "R".into(),
            description: None,
            mime_type: None,
        }],
        None,
    );
    assert!(r.read_resource("s", "r://1").is_ok());
    assert!(r.read_resource("s", "r://missing").is_err());
}

#[test]
fn mcp_tool_registry_read_resource_disconnected() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::Disconnected, vec![], vec![], None);
    assert!(r.read_resource("s", "r://1").is_err());
}

#[test]
fn mcp_tool_registry_read_resource_missing_server() {
    let r = McpToolRegistry::new();
    assert!(r.read_resource("missing", "r://1").is_err());
}

#[test]
fn mcp_tool_registry_call_tool_missing_server() {
    let r = McpToolRegistry::new();
    assert!(r.call_tool("missing", "t", &serde_json::json!({})).is_err());
}

#[test]
fn mcp_tool_registry_call_tool_disconnected() {
    let r = McpToolRegistry::new();
    r.register_server("s", McpConnectionStatus::Disconnected, vec![], vec![], None);
    assert!(r.call_tool("s", "t", &serde_json::json!({})).is_err());
}

#[test]
fn mcp_tool_registry_call_tool_unknown_tool() {
    let r = McpToolRegistry::new();
    r.register_server(
        "s",
        McpConnectionStatus::Connected,
        vec![McpToolInfo {
            name: "t".into(),
            description: None,
            input_schema: None,
        }],
        vec![],
        None,
    );
    assert!(r.call_tool("s", "unknown", &serde_json::json!({})).is_err());
}

#[test]
fn mcp_tool_registry_call_tool_no_manager() {
    let r = McpToolRegistry::new();
    r.register_server(
        "s",
        McpConnectionStatus::Connected,
        vec![McpToolInfo {
            name: "t".into(),
            description: None,
            input_schema: None,
        }],
        vec![],
        None,
    );
    assert!(r.call_tool("s", "t", &serde_json::json!({})).is_err());
}

// ---------------------------------------------------------------------------
// lsp_client
// ---------------------------------------------------------------------------

#[test]
fn lsp_action_from_str() {
    assert_eq!(
        LspAction::from_str("diagnostics"),
        Some(LspAction::Diagnostics)
    );
    assert_eq!(LspAction::from_str("hover"), Some(LspAction::Hover));
    assert_eq!(
        LspAction::from_str("definition"),
        Some(LspAction::Definition)
    );
    assert_eq!(
        LspAction::from_str("goto_definition"),
        Some(LspAction::Definition)
    );
    assert_eq!(
        LspAction::from_str("references"),
        Some(LspAction::References)
    );
    assert_eq!(
        LspAction::from_str("find_references"),
        Some(LspAction::References)
    );
    assert_eq!(
        LspAction::from_str("completion"),
        Some(LspAction::Completion)
    );
    assert_eq!(
        LspAction::from_str("completions"),
        Some(LspAction::Completion)
    );
    assert_eq!(
        LspAction::from_str("symbols"),
        Some(LspAction::Symbols)
    );
    assert_eq!(
        LspAction::from_str("document_symbols"),
        Some(LspAction::Symbols)
    );
    assert_eq!(LspAction::from_str("format"), Some(LspAction::Format));
    assert_eq!(
        LspAction::from_str("formatting"),
        Some(LspAction::Format)
    );
    assert_eq!(LspAction::from_str("unknown"), None);
}

#[test]
fn lsp_action_equality() {
    assert_eq!(LspAction::Diagnostics, LspAction::Diagnostics);
    assert_ne!(LspAction::Hover, LspAction::Format);
}

#[test]
fn lsp_action_serde_roundtrip() {
    let j = serde_json::to_string(&LspAction::Definition).unwrap();
    let back: LspAction = serde_json::from_str(&j).unwrap();
    assert_eq!(back, LspAction::Definition);
}

#[test]
fn lsp_server_status_display() {
    assert_eq!(LspServerStatus::Connected.to_string(), "connected");
    assert_eq!(LspServerStatus::Disconnected.to_string(), "disconnected");
    assert_eq!(LspServerStatus::Starting.to_string(), "starting");
    assert_eq!(LspServerStatus::Error.to_string(), "error");
}

#[test]
fn lsp_server_status_equality() {
    assert_eq!(LspServerStatus::Connected, LspServerStatus::Connected);
    assert_ne!(LspServerStatus::Connected, LspServerStatus::Error);
}

#[test]
fn lsp_server_status_serde_roundtrip() {
    let j = serde_json::to_string(&LspServerStatus::Starting).unwrap();
    let back: LspServerStatus = serde_json::from_str(&j).unwrap();
    assert_eq!(back, LspServerStatus::Starting);
}

#[test]
fn lsp_diagnostic_serde_roundtrip() {
    let d = LspDiagnostic {
        path: "src/main.rs".into(),
        line: 10,
        character: 5,
        severity: "error".into(),
        message: "type mismatch".into(),
        source: Some("rust-analyzer".into()),
    };
    let j = serde_json::to_string(&d).unwrap();
    let back: LspDiagnostic = serde_json::from_str(&j).unwrap();
    assert_eq!(back.line, 10);
}

#[test]
fn lsp_location_serde_roundtrip() {
    let l = LspLocation {
        path: "src/lib.rs".into(),
        line: 5,
        character: 3,
        end_line: Some(5),
        end_character: Some(10),
        preview: Some("fn main()".into()),
    };
    let j = serde_json::to_string(&l).unwrap();
    let back: LspLocation = serde_json::from_str(&j).unwrap();
    assert_eq!(back.line, 5);
}

#[test]
fn lsp_hover_result_serde_roundtrip() {
    let h = LspHoverResult {
        content: "type: i32".into(),
        language: Some("rust".into()),
    };
    let j = serde_json::to_string(&h).unwrap();
    let back: LspHoverResult = serde_json::from_str(&j).unwrap();
    assert_eq!(back.content, "type: i32");
}

#[test]
fn lsp_completion_item_serde_roundtrip() {
    let c = LspCompletionItem {
        label: "main".into(),
        kind: Some("function".into()),
        detail: Some("fn main()".into()),
        insert_text: Some("main()".into()),
    };
    let j = serde_json::to_string(&c).unwrap();
    let back: LspCompletionItem = serde_json::from_str(&j).unwrap();
    assert_eq!(back.label, "main");
}

#[test]
fn lsp_symbol_serde_roundtrip() {
    let s = LspSymbol {
        name: "main".into(),
        kind: "function".into(),
        path: "src/main.rs".into(),
        line: 1,
        character: 0,
    };
    let j = serde_json::to_string(&s).unwrap();
    let back: LspSymbol = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, "main");
}

#[test]
fn lsp_server_state_serde_roundtrip() {
    let s = LspServerState {
        language: "rust".into(),
        status: LspServerStatus::Connected,
        root_path: Some("/workspace".into()),
        capabilities: vec!["hover".into()],
        diagnostics: vec![],
    };
    let j = serde_json::to_string(&s).unwrap();
    let back: LspServerState = serde_json::from_str(&j).unwrap();
    assert_eq!(back.language, "rust");
}

#[test]
fn lsp_registry_new() {
    let r = LspRegistry::new();
    assert!(r.is_empty());
}

#[test]
fn lsp_registry_register_and_get() {
    let r = LspRegistry::new();
    r.register(
        "rust",
        LspServerStatus::Connected,
        Some("/ws"),
        vec!["hover".into()],
    );
    assert!(r.get("rust").is_some());
    assert_eq!(r.len(), 1);
}

#[test]
fn lsp_registry_get_missing() {
    let r = LspRegistry::new();
    assert!(r.get("missing").is_none());
}

#[test]
fn lsp_registry_find_server_for_path() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    r.register("typescript", LspServerStatus::Connected, None, vec![]);
    assert_eq!(
        r.find_server_for_path("src/main.rs").unwrap().language,
        "rust"
    );
    assert_eq!(
        r.find_server_for_path("src/index.ts").unwrap().language,
        "typescript"
    );
    assert!(r.find_server_for_path("data.csv").is_none());
}

#[test]
fn lsp_registry_list_servers() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    r.register("python", LspServerStatus::Starting, None, vec![]);
    assert_eq!(r.list_servers().len(), 2);
}

#[test]
fn lsp_registry_disconnect() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    assert!(r.disconnect("rust").is_some());
    assert!(r.is_empty());
}

#[test]
fn lsp_registry_add_diagnostics() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    r.add_diagnostics(
        "rust",
        vec![LspDiagnostic {
            path: "src/main.rs".into(),
            line: 1,
            character: 0,
            severity: "error".into(),
            message: "err".into(),
            source: None,
        }],
    )
    .unwrap();
    assert_eq!(r.get_diagnostics("src/main.rs").len(), 1);
}

#[test]
fn lsp_registry_add_diagnostics_missing() {
    let r = LspRegistry::new();
    assert!(r.add_diagnostics("missing", vec![]).is_err());
}

#[test]
fn lsp_registry_clear_diagnostics() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    r.add_diagnostics(
        "rust",
        vec![LspDiagnostic {
            path: "a.rs".into(),
            line: 0,
            character: 0,
            severity: "error".into(),
            message: "e".into(),
            source: None,
        }],
    )
    .unwrap();
    r.clear_diagnostics("rust").unwrap();
    assert!(r.get_diagnostics("a.rs").is_empty());
}

#[test]
fn lsp_registry_clear_diagnostics_missing() {
    let r = LspRegistry::new();
    assert!(r.clear_diagnostics("missing").is_err());
}

#[test]
fn lsp_registry_dispatch_diagnostics() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    let result = r
        .dispatch("diagnostics", Some("src/main.rs"), None, None, None)
        .unwrap();
    assert_eq!(result["action"], "diagnostics");
}

#[test]
fn lsp_registry_dispatch_diagnostics_no_path() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    let result = r
        .dispatch("diagnostics", None, None, None, None)
        .unwrap();
    assert_eq!(result["action"], "diagnostics");
}

#[test]
fn lsp_registry_dispatch_hover() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    let result = r
        .dispatch("hover", Some("src/main.rs"), Some(10), Some(5), None)
        .unwrap();
    assert_eq!(result["action"], "hover");
}

#[test]
fn lsp_registry_dispatch_unknown_action() {
    let r = LspRegistry::new();
    assert!(r.dispatch("bogus", None, None, None, None).is_err());
}

#[test]
fn lsp_registry_dispatch_requires_path() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Connected, None, vec![]);
    assert!(r.dispatch("hover", None, Some(1), Some(0), None).is_err());
}

#[test]
fn lsp_registry_dispatch_no_server_for_path() {
    let r = LspRegistry::new();
    assert!(
        r.dispatch("hover", Some("notes.md"), Some(1), Some(0), None)
            .is_err()
    );
}

#[test]
fn lsp_registry_dispatch_disconnected_server() {
    let r = LspRegistry::new();
    r.register("rust", LspServerStatus::Disconnected, None, vec![]);
    assert!(
        r.dispatch("hover", Some("src/main.rs"), Some(1), Some(0), None)
            .is_err()
    );
}
