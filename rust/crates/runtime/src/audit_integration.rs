use security::audit::{AuditAction, AuditLog};
use security::generate_audit_keypair;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct SessionAuditor {
    audit_log: Arc<Mutex<AuditLog>>,
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
    session_id: String,
    started_at: u64,
    tool_call_count: Arc<std::sync::atomic::AtomicU64>,
    block_size: usize,
}

impl SessionAuditor {
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        let (sk, vk) = generate_audit_keypair();

        let mut log = AuditLog::new();
        log.log(
            AuditAction::SessionStart,
            Some(format!("session:{session_id}")),
        );

        Self {
            audit_log: Arc::new(Mutex::new(log)),
            signing_key: Some(sk),
            verifying_key: Some(vk),
            session_id: session_id.to_string(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tool_call_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            block_size: 100,
        }
    }

    #[must_use]
    pub fn new_without_signing(session_id: &str) -> Self {
        let mut log = AuditLog::new();
        log.log(
            AuditAction::SessionStart,
            Some(format!("session:{session_id}")),
        );

        Self {
            audit_log: Arc::new(Mutex::new(log)),
            signing_key: None,
            verifying_key: None,
            session_id: session_id.to_string(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tool_call_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            block_size: 100,
        }
    }

    pub fn log(&self, action: AuditAction, target: Option<String>) {
        let count = self.tool_call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let mut log = self.audit_log.lock().unwrap();
        log.log(action, target);

        if count.is_multiple_of(self.block_size as u64) {
            if let Some(ref sk) = self.signing_key {
                log.sign_block(sk);
            }
        }
    }

    pub fn record_tool_call(&self, tool_name: &str, success: bool) {
        self.log(
            if success {
                AuditAction::ToolCallEnd
            } else {
                AuditAction::ToolExecute
            },
            Some(format!("tool:{tool_name}")),
        );
    }

    pub fn record_permission(&self, granted: bool, resource: &str) {
        self.log(
            if granted {
                AuditAction::PermissionGrant
            } else {
                AuditAction::PermissionDeny
            },
            Some(resource.to_string()),
        );
    }

    pub fn record_provider_switch(&self, provider: &str) {
        self.log(AuditAction::ProviderSwitch, Some(provider.to_string()));
    }

    pub fn end_session(&self) {
        self.log(
            AuditAction::SessionEnd,
            Some(format!("session:{}", self.session_id)),
        );
    }

    #[must_use]
    pub fn verify_chain(&self) -> bool {
        self.audit_log.lock().unwrap().verify()
    }

    pub fn verify_integrity(&self) -> Result<(), Vec<String>> {
        self.audit_log.lock().unwrap().verify_chain_integrity()
    }

    #[must_use]
    pub fn log_ref(&self) -> Arc<Mutex<AuditLog>> {
        self.audit_log.clone()
    }

    #[must_use]
    pub fn signing_key(&self) -> Option<&SigningKey> {
        self.signing_key.as_ref()
    }

    #[must_use]
    pub fn verifying_key(&self) -> Option<&VerifyingKey> {
        self.verifying_key.as_ref()
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn tool_call_count(&self) -> u64 {
        self.tool_call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - self.started_at
    }
}

static GLOBAL_AUDITOR: OnceLock<Mutex<Option<SessionAuditor>>> = OnceLock::new();

pub fn global_auditor() -> &'static Mutex<Option<SessionAuditor>> {
    GLOBAL_AUDITOR.get_or_init(|| Mutex::new(None))
}

pub fn init_global_auditor(session_id: &str) {
    let auditor = SessionAuditor::new(session_id);
    let mut guard = global_auditor().lock().unwrap();
    *guard = Some(auditor);
}

pub fn with_auditor<F, R>(f: F) -> R
where
    F: FnOnce(&SessionAuditor) -> R,
{
    let guard = global_auditor().lock().unwrap();
    if let Some(ref auditor) = *guard {
        f(auditor)
    } else {
        panic!("SessionAuditor not initialized. Call init_global_auditor() first.");
    }
}

pub fn try_with_auditor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&SessionAuditor) -> R,
{
    let guard = global_auditor().lock().unwrap();
    guard.as_ref().map(f)
}

pub struct AuditGuard {
    auditor: Arc<Mutex<AuditLog>>,
    tool_name: String,
    started_at: std::time::Instant,
}

impl AuditGuard {
    pub fn new(auditor: Arc<Mutex<AuditLog>>, tool_name: &str) -> Self {
        {
            let mut log = auditor.lock().unwrap();
            log.log(
                AuditAction::ToolCallStart,
                Some(format!("tool:{tool_name}")),
            );
        }
        Self {
            auditor,
            tool_name: tool_name.to_string(),
            started_at: std::time::Instant::now(),
        }
    }

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        let mut log = self.auditor.lock().unwrap();
        log.log(
            AuditAction::ToolCallEnd,
            Some(format!(
                "tool:{} duration:{}ms",
                self.tool_name,
                self.elapsed().as_millis()
            )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_auditor_create() {
        let auditor = SessionAuditor::new("test-session");
        assert_eq!(auditor.session_id(), "test-session");
        assert!(auditor.verify_chain());
    }

    #[test]
    fn test_session_auditor_log() {
        let auditor = SessionAuditor::new("test-session");
        auditor.log(AuditAction::ToolExecute, Some("read".to_string()));
        assert_eq!(auditor.tool_call_count(), 1);
        assert!(auditor.verify_chain());
    }

    #[test]
    fn test_session_auditor_record_tool_call() {
        let auditor = SessionAuditor::new("test-session");
        auditor.record_tool_call("read", true);
        assert!(auditor.verify_chain());
    }

    #[test]
    fn test_session_auditor_record_permission() {
        let auditor = SessionAuditor::new("test-session");
        auditor.record_permission(true, "write:/tmp/test");
        auditor.record_permission(false, "delete:/etc/passwd");
        assert!(auditor.verify_chain());
    }

    #[test]
    fn test_session_auditor_end_session() {
        let auditor = SessionAuditor::new("test-session");
        auditor.end_session();
        assert!(auditor.verify_chain());
    }

    #[test]
    fn test_session_auditor_integrity() {
        let auditor = SessionAuditor::new("test-session");
        assert!(auditor.verify_integrity().is_ok());
    }

    #[test]
    fn test_session_auditor_uptime() {
        let auditor = SessionAuditor::new("test-session");
        assert!(auditor.uptime_secs() == 0);
    }

    #[test]
    fn test_session_auditor_without_signing() {
        let auditor = SessionAuditor::new_without_signing("test");
        assert!(auditor.signing_key().is_none());
        assert!(auditor.verify_chain());
    }

    #[test]
    fn test_audit_guard() {
        let auditor = SessionAuditor::new("test-session");
        let log = auditor.log_ref();
        {
            let _guard = AuditGuard::new(log.clone(), "bash");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let log = log.lock().unwrap();
        assert!(log.len() >= 3);
        assert!(log.verify());
    }

    #[test]
    fn test_global_auditor_lifecycle() {
        let _lock = crate::test_env_lock();

        // Initially no global auditor
        {
            let guard = global_auditor().lock().unwrap();
            assert!(guard.is_none());
        }

        // Initialize
        init_global_auditor("global-test");
        let result = with_auditor(|a| a.session_id().to_string());
        assert_eq!(result, "global-test");

        // try_with works
        let result = try_with_auditor(|a| a.session_id().to_string());
        assert_eq!(result, Some("global-test".to_string()));

        // Global exists
        {
            let guard = global_auditor().lock().unwrap();
            assert!(guard.is_some());
        }
    }

    #[test]
    fn test_record_provider_switch() {
        let auditor = SessionAuditor::new("test-session");
        auditor.record_provider_switch("deepseek");
        assert!(auditor.verify_chain());
    }
}
