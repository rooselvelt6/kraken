//! Enterprise features: audit log enhancement and rate limiting

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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let (requests, tokens) = limiter.get_remaining("user1");
        assert_eq!(requests, 9);
    }
}
