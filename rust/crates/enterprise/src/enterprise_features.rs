/// Enterprise features: audit log enhancement and rate limiting
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// ============================================================================
// Enterprise Audit Log
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseAuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub session_id: String,
    pub action: AuditAction,
    pub resource: String,
    pub result: AuditResult,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    Login,
    Logout,
    ApiKeySet,
    ApiKeyClear,
    ConfigChange,
    SessionCreate,
    SessionEnd,
    ToolExecute,
    FileRead,
    FileWrite,
    FileDelete,
    ProviderSwitch,
    ModelChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Partial,
    Denied,
}

impl EnterpriseAuditEntry {
    pub fn new(
        user_id: &str,
        session_id: &str,
        action: AuditAction,
        resource: &str,
        result: AuditResult,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            action,
            resource: resource.to_string(),
            result,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }

    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

pub struct EnterpriseAuditLog {
    entries: Arc<Mutex<Vec<EnterpriseAuditEntry>>>,
    max_entries: usize,
}

impl EnterpriseAuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            max_entries,
        }
    }

    pub fn log(&self, entry: EnterpriseAuditEntry) {
        let mut guard = self.entries.lock().unwrap();
        guard.push(entry);

        // Prune old entries
        while guard.len() > self.max_entries {
            guard.remove(0);
        }
    }

    pub fn query(
        &self,
        user_id: Option<&str>,
        action: Option<AuditAction>,
    ) -> Vec<EnterpriseAuditEntry> {
        let guard = self.entries.lock().unwrap();
        guard
            .iter()
            .filter(|e| {
                let user_match = user_id.map_or(true, |u| e.user_id == u);
                let action_match = action.map_or(true, |a| e.action == a);
                user_match && action_match
            })
            .cloned()
            .collect()
    }

    pub fn export_json(&self) -> String {
        let guard = self.entries.lock().unwrap();
        serde_json::to_string(&*guard).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

// ============================================================================
// Rate Limiting
// ============================================================================

#[derive(Debug, Clone)]
pub struct RateLimitBucket {
    pub requests_per_minute: u32,
    pub tokens_per_minute: u64,
    pub burst: u32,
    requests_used: u32,
    tokens_used: u64,
    window_start: std::time::Instant,
}

impl RateLimitBucket {
    pub fn new(requests_per_minute: u32, tokens_per_minute: u64, burst: u32) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            burst,
            requests_used: 0,
            tokens_used: 0,
            window_start: std::time::Instant::now(),
        }
    }

    pub fn allows(&mut self, tokens: u64) -> bool {
        // Reset window if expired (1 minute)
        if self.window_start.elapsed() > std::time::Duration::from_secs(60) {
            self.requests_used = 0;
            self.tokens_used = 0;
            self.window_start = std::time::Instant::now();
        }

        // Check burst limit
        if self.requests_used >= self.burst {
            return false;
        }

        // Check rate limits
        if self.requests_used >= self.requests_per_minute {
            return false;
        }

        if self.tokens_used + tokens > self.tokens_per_minute {
            return false;
        }

        // Consume
        self.requests_used += 1;
        self.tokens_used += tokens;

        true
    }

    pub fn remaining_requests(&self) -> u32 {
        self.requests_per_minute.saturating_sub(self.requests_used)
    }

    pub fn remaining_tokens(&self) -> u64 {
        self.tokens_per_minute.saturating_sub(self.tokens_used)
    }

    pub fn reset(&mut self) {
        self.requests_used = 0;
        self.tokens_used = 0;
        self.window_start = std::time::Instant::now();
    }
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, RateLimitBucket>>,
    default_requests: u32,
    default_tokens: u64,
    default_burst: u32,
}

impl RateLimiter {
    pub fn new(default_requests: u32, default_tokens: u64, default_burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            default_requests,
            default_tokens,
            default_burst,
        }
    }

    pub fn check(&self, key: &str, tokens: u64) -> bool {
        let mut guard = self.buckets.lock().unwrap();

        let bucket = guard.entry(key.to_string()).or_insert_with(|| {
            RateLimitBucket::new(
                self.default_requests,
                self.default_tokens,
                self.default_burst,
            )
        });

        bucket.allows(tokens)
    }

    pub fn get_remaining(&self, key: &str) -> (u32, u64) {
        let guard = self.buckets.lock().unwrap();

        if let Some(bucket) = guard.get(key) {
            (bucket.remaining_requests(), bucket.remaining_tokens())
        } else {
            (self.default_requests, self.default_tokens)
        }
    }

    pub fn reset(&self, key: &str) {
        let mut guard = self.buckets.lock().unwrap();
        if let Some(bucket) = guard.get_mut(key) {
            bucket.reset();
        }
    }
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    pub rate_limit_requests: u32,
    pub rate_limit_tokens: u64,
    pub rate_limit_burst: u32,
    pub audit_max_entries: usize,
    pub audit_retention_days: u32,
    pub enable_sso: bool,
    pub sso_provider: Option<String>,
    pub enable_heuristic_engine: bool,
    pub hae_critical_threshold: f64,
    pub hae_high_threshold: f64,
    pub hae_medium_threshold: f64,
    pub circuit_breaker_failure_threshold: u32,
    pub circuit_breaker_recovery_timeout_ms: u64,
    pub circuit_breaker_success_threshold: u32,
    pub enable_health_probes: bool,
    pub health_probe_interval_ms: u64,
    pub health_probe_timeout_threshold_ms: f64,
    pub adaptive_rate_limiting: bool,
    pub rate_limiter_base_capacity: f64,
    pub rate_limiter_refill_rate: f64,
    pub rate_limiter_max_capacity: f64,
    pub rate_limiter_min_capacity: f64,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            rate_limit_requests: 60,
            rate_limit_tokens: 100_000,
            rate_limit_burst: 10,
            audit_max_entries: 10_000,
            audit_retention_days: 90,
            enable_sso: false,
            sso_provider: None,
            enable_heuristic_engine: true,
            hae_critical_threshold: 0.95,
            hae_high_threshold: 0.80,
            hae_medium_threshold: 0.60,
            circuit_breaker_failure_threshold: 5,
            circuit_breaker_recovery_timeout_ms: 30_000,
            circuit_breaker_success_threshold: 2,
            enable_health_probes: true,
            health_probe_interval_ms: 5_000,
            health_probe_timeout_threshold_ms: 10_000.0,
            adaptive_rate_limiting: true,
            rate_limiter_base_capacity: 60.0,
            rate_limiter_refill_rate: 1.0,
            rate_limiter_max_capacity: 120.0,
            rate_limiter_min_capacity: 10.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_enterprise_audit_entry() {
        let entry = EnterpriseAuditEntry::new(
            "user1",
            "session1",
            AuditAction::ToolExecute,
            "read",
            AuditResult::Success,
        );

        assert!(!entry.id.is_empty());
        assert_eq!(entry.action, AuditAction::ToolExecute);
    }

    #[test]
    fn test_audit_log() {
        let log = EnterpriseAuditLog::new(100);

        let entry = EnterpriseAuditEntry::new(
            "user1",
            "session1",
            AuditAction::Login,
            "system",
            AuditResult::Success,
        );

        log.log(entry);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_rate_limit_bucket() {
        let mut bucket = RateLimitBucket::new(10, 1000, 5);

        assert!(bucket.allows(100));
        assert!(bucket.allows(100));
        assert!(!bucket.allows(2000)); // exceeds tokens

        assert_eq!(bucket.remaining_requests(), 8);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 100, 5);

        assert!(limiter.check("user1", 50));
        assert!(limiter.check("user2", 50));

        let (requests, _tokens) = limiter.get_remaining("user1");
        assert_eq!(requests, 9);
    }

    #[test]
    fn test_audit_entry_new_defaults() {
        let entry = EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Logout,
            "/api/logout",
            AuditResult::Success,
        );
        assert!(!entry.id.is_empty());
        assert_eq!(entry.user_id, "u1");
        assert_eq!(entry.session_id, "s1");
        assert_eq!(entry.action, AuditAction::Logout);
        assert_eq!(entry.resource, "/api/logout");
        assert_eq!(entry.result, AuditResult::Success);
        assert!(entry.ip_address.is_none());
        assert!(entry.user_agent.is_none());
        assert!(entry.metadata.is_empty());
    }

    #[test]
    fn test_audit_entry_builder_chain() {
        let entry = EnterpriseAuditEntry::new(
            "user1",
            "s1",
            AuditAction::ConfigChange,
            "config",
            AuditResult::Partial,
        )
        .with_ip("192.168.1.1")
        .with_user_agent("Mozilla/5.0")
        .with_metadata("key1", "val1")
        .with_metadata("key2", "val2");

        assert_eq!(entry.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(entry.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(entry.metadata.get("key1"), Some(&"val1".to_string()));
        assert_eq!(entry.metadata.get("key2"), Some(&"val2".to_string()));
    }

    #[test]
    fn test_audit_entry_to_json() {
        let entry = EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Login,
            "system",
            AuditResult::Success,
        );
        let json = entry.to_json();
        assert!(!json.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["user_id"], "u1");
        assert_eq!(parsed["action"], "Login");
    }

    #[test]
    fn test_audit_entry_serialization_roundtrip() {
        let entry = EnterpriseAuditEntry::new(
            "user1",
            "session1",
            AuditAction::FileRead,
            "/etc/passwd",
            AuditResult::Denied,
        )
        .with_ip("10.0.0.1")
        .with_metadata("reason", "forbidden");

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: EnterpriseAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.user_id, "user1");
        assert_eq!(deserialized.action, AuditAction::FileRead);
        assert_eq!(deserialized.result, AuditResult::Denied);
        assert_eq!(deserialized.ip_address, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_audit_entry_unique_ids() {
        let e1 = EnterpriseAuditEntry::new("u1", "s1", AuditAction::Login, "r", AuditResult::Success);
        let e2 = EnterpriseAuditEntry::new("u2", "s2", AuditAction::Logout, "r", AuditResult::Success);
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn test_audit_log_max_entries_eviction() {
        let log = EnterpriseAuditLog::new(3);

        for i in 0..5 {
            log.log(EnterpriseAuditEntry::new(
                &format!("u{}", i),
                "s1",
                AuditAction::ToolExecute,
                "r",
                AuditResult::Success,
            ));
        }

        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_audit_log_query_by_user() {
        let log = EnterpriseAuditLog::new(100);
        log.log(EnterpriseAuditEntry::new(
            "alice",
            "s1",
            AuditAction::Login,
            "system",
            AuditResult::Success,
        ));
        log.log(EnterpriseAuditEntry::new(
            "bob",
            "s2",
            AuditAction::Login,
            "system",
            AuditResult::Success,
        ));
        log.log(EnterpriseAuditEntry::new(
            "alice",
            "s3",
            AuditAction::Logout,
            "system",
            AuditResult::Success,
        ));

        let alice_entries = log.query(Some("alice"), None);
        assert_eq!(alice_entries.len(), 2);
        let bob_entries = log.query(Some("bob"), None);
        assert_eq!(bob_entries.len(), 1);
    }

    #[test]
    fn test_audit_log_query_by_action() {
        let log = EnterpriseAuditLog::new(100);
        log.log(EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Login,
            "system",
            AuditResult::Success,
        ));
        log.log(EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Logout,
            "system",
            AuditResult::Success,
        ));
        log.log(EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::ToolExecute,
            "r",
            AuditResult::Success,
        ));

        let logins = log.query(None, Some(AuditAction::Login));
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].action, AuditAction::Login);
    }

    #[test]
    fn test_audit_log_query_combined_filters() {
        let log = EnterpriseAuditLog::new(100);
        log.log(EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Login,
            "sys",
            AuditResult::Success,
        ));
        log.log(EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Login,
            "sys",
            AuditResult::Failure,
        ));
        log.log(EnterpriseAuditEntry::new(
            "u2",
            "s2",
            AuditAction::Login,
            "sys",
            AuditResult::Success,
        ));

        let result = log.query(Some("u1"), Some(AuditAction::Login));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_audit_log_export_json() {
        let log = EnterpriseAuditLog::new(100);
        log.log(EnterpriseAuditEntry::new(
            "u1",
            "s1",
            AuditAction::Login,
            "sys",
            AuditResult::Success,
        ));

        let json = log.export_json();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_audit_log_empty() {
        let log = EnterpriseAuditLog::new(10);
        assert_eq!(log.len(), 0);
        let results = log.query(None, None);
        assert!(results.is_empty());
        let json = log.export_json();
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_rate_limit_bucket_new() {
        let bucket = RateLimitBucket::new(60, 100000, 10);
        assert_eq!(bucket.requests_per_minute, 60);
        assert_eq!(bucket.tokens_per_minute, 100000);
        assert_eq!(bucket.burst, 10);
        assert_eq!(bucket.remaining_requests(), 60);
        assert_eq!(bucket.remaining_tokens(), 100000);
    }

    #[test]
    fn test_rate_limit_bucket_burst_limit() {
        let mut bucket = RateLimitBucket::new(3, 10000, 2);
        assert!(bucket.allows(1)); // request 1, burst 1
        assert!(bucket.allows(1)); // request 2, burst 2
        assert!(!bucket.allows(1)); // burst exceeded (2 >= 2)
    }

    #[test]
    fn test_rate_limit_bucket_token_limit() {
        let mut bucket = RateLimitBucket::new(100, 50, 100);
        assert!(bucket.allows(30));
        assert!(bucket.allows(20)); // exactly at token limit
        assert!(!bucket.allows(1)); // would exceed tokens
    }

    #[test]
    fn test_rate_limit_bucket_request_limit() {
        let mut bucket = RateLimitBucket::new(2, 100000, 100);
        assert!(bucket.allows(1));
        assert!(bucket.allows(1));
        assert!(!bucket.allows(1)); // request count exceeded
    }

    #[test]
    fn test_rate_limit_bucket_reset() {
        let mut bucket = RateLimitBucket::new(5, 1000, 5);
        bucket.allows(100);
        bucket.allows(100);
        assert_eq!(bucket.remaining_requests(), 3);

        bucket.reset();
        assert_eq!(bucket.remaining_requests(), 5);
        assert_eq!(bucket.remaining_tokens(), 1000);
    }

    #[test]
    fn test_rate_limit_bucket_remaining_saturates() {
        let bucket = RateLimitBucket::new(5, 1000, 5);
        // remaining_requests should saturate at 0 if somehow overspent
        assert_eq!(bucket.remaining_requests(), 5);
        assert_eq!(bucket.remaining_tokens(), 1000);
    }

    #[test]
    fn test_rate_limit_bucket_zero_tokens() {
        let mut bucket = RateLimitBucket::new(10, 100, 10);
        // allows(0) consumes 0 tokens and 1 request slot
        assert!(bucket.allows(0));
        assert_eq!(bucket.remaining_requests(), 9);
        assert_eq!(bucket.remaining_tokens(), 100);
    }

    #[test]
    fn test_rate_limiter_multiple_keys() {
        let limiter = RateLimiter::new(10, 1000, 5);

        limiter.check("user_a", 100);
        limiter.check("user_a", 100);
        limiter.check("user_b", 100);

        let (req_a, _) = limiter.get_remaining("user_a");
        assert_eq!(req_a, 8);
        let (req_b, _) = limiter.get_remaining("user_b");
        assert_eq!(req_b, 9);
    }

    #[test]
    fn test_rate_limiter_get_remaining_unknown_key() {
        let limiter = RateLimiter::new(20, 5000, 10);
        let (req, tokens) = limiter.get_remaining("nonexistent");
        assert_eq!(req, 20);
        assert_eq!(tokens, 5000);
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(10, 1000, 10);
        limiter.check("user1", 500);
        limiter.check("user1", 500);
        let (req, _) = limiter.get_remaining("user1");
        assert_eq!(req, 8);

        limiter.reset("user1");
        let (req, _) = limiter.get_remaining("user1");
        assert_eq!(req, 10);
    }

    #[test]
    fn test_rate_limiter_reset_nonexistent_key() {
        let limiter = RateLimiter::new(10, 1000, 5);
        limiter.reset("nonexistent"); // should not panic
    }

    #[test]
    fn test_rate_limiter_concurrent_access() {
        let limiter = Arc::new(RateLimiter::new(100, 10000, 50));
        let mut handles = vec![];

        for i in 0..10 {
            let limiter = limiter.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..5 {
                    limiter.check(&format!("user_{}", i), 10);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        for i in 0..10 {
            let (req, _) = limiter.get_remaining(&format!("user_{}", i));
            assert_eq!(req, 95);
        }
    }

    #[test]
    fn test_audit_log_concurrent_access() {
        let log = Arc::new(EnterpriseAuditLog::new(1000));
        let mut handles = vec![];

        for i in 0..10 {
            let log = log.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..5 {
                    log.log(EnterpriseAuditEntry::new(
                        &format!("user_{}", i),
                        "s1",
                        AuditAction::ToolExecute,
                        "r",
                        AuditResult::Success,
                    ));
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(log.len(), 50);
    }

    #[test]
    fn test_enterprise_config_default() {
        let config = EnterpriseConfig::default();
        assert_eq!(config.rate_limit_requests, 60);
        assert_eq!(config.rate_limit_tokens, 100_000);
        assert_eq!(config.rate_limit_burst, 10);
        assert_eq!(config.audit_max_entries, 10_000);
        assert_eq!(config.audit_retention_days, 90);
        assert!(!config.enable_sso);
        assert!(config.sso_provider.is_none());
        assert!(config.enable_heuristic_engine);
        assert!(config.enable_health_probes);
        assert!(config.adaptive_rate_limiting);
    }

    #[test]
    fn test_enterprise_config_serialization() {
        let config = EnterpriseConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EnterpriseConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rate_limit_requests, 60);
        assert_eq!(deserialized.hae_critical_threshold, 0.95);
        assert_eq!(deserialized.circuit_breaker_failure_threshold, 5);
    }

    #[test]
    fn test_enterprise_config_custom() {
        let config = EnterpriseConfig {
            enable_sso: true,
            sso_provider: Some("okta".to_string()),
            rate_limit_requests: 120,
            ..Default::default()
        };
        assert!(config.enable_sso);
        assert_eq!(config.sso_provider, Some("okta".to_string()));
        assert_eq!(config.rate_limit_requests, 120);
    }

    #[test]
    fn test_audit_action_serialization_variants() {
        let actions = [
            AuditAction::Login,
            AuditAction::Logout,
            AuditAction::ApiKeySet,
            AuditAction::ApiKeyClear,
            AuditAction::ConfigChange,
            AuditAction::SessionCreate,
            AuditAction::SessionEnd,
            AuditAction::ToolExecute,
            AuditAction::FileRead,
            AuditAction::FileWrite,
            AuditAction::FileDelete,
            AuditAction::ProviderSwitch,
            AuditAction::ModelChange,
        ];

        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let deserialized: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", action), format!("{:?}", deserialized));
        }
    }

    #[test]
    fn test_audit_result_serialization_variants() {
        let results = [
            AuditResult::Success,
            AuditResult::Failure,
            AuditResult::Partial,
            AuditResult::Denied,
        ];

        for result in &results {
            let json = serde_json::to_string(result).unwrap();
            let deserialized: AuditResult = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", result), format!("{:?}", deserialized));
        }
    }
}
