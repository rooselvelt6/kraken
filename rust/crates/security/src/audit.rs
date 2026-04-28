//! Audit logging with hash chain for integrity verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 10000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    ApiKeySet,
    ApiKeyCleared,
    ConfigEncrypt,
    ConfigDecrypt,
    SessionStart,
    SessionEnd,
    ToolExecute,
    FileRead,
    FileWrite,
    FileDelete,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::ApiKeySet => write!(f, "API_KEY_SET"),
            AuditAction::ApiKeyCleared => write!(f, "API_KEY_CLEARED"),
            AuditAction::ConfigEncrypt => write!(f, "CONFIG_ENCRYPT"),
            AuditAction::ConfigDecrypt => write!(f, "CONFIG_DECRYPT"),
            AuditAction::SessionStart => write!(f, "SESSION_START"),
            AuditAction::SessionEnd => write!(f, "SESSION_END"),
            AuditAction::ToolExecute => write!(f, "TOOL_EXECUTE"),
            AuditAction::FileRead => write!(f, "FILE_READ"),
            AuditAction::FileWrite => write!(f, "FILE_WRITE"),
            AuditAction::FileDelete => write!(f, "FILE_DELETE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub action: AuditAction,
    pub target: Option<String>,
    pub entry_hash: [u8; 32],
}

impl AuditEntry {
    pub fn new(action: AuditAction, target: Option<String>, prev_hash: [u8; 32]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry_hash = Self::compute_hash(timestamp, &action, target.as_deref(), prev_hash);

        Self {
            timestamp,
            action,
            target,
            entry_hash,
        }
    }

    fn compute_hash(
        timestamp: u64,
        action: &AuditAction,
        target: Option<&str>,
        prev: [u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(action.to_string().as_bytes());
        if let Some(t) = target {
            hasher.update(t.as_bytes());
        }
        hasher.finalize().into()
    }
}

pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
    previous_hash: [u8; 32],
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_ENTRIES),
            previous_hash: [0u8; 32],
        }
    }

    pub fn log(&mut self, action: AuditAction, target: Option<String>) {
        let entry = AuditEntry::new(action, target, self.previous_hash);
        self.previous_hash = entry.entry_hash;

        self.entries.push_back(entry);

        if self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
        }
    }

    pub fn verify(&self) -> bool {
        let mut prev = [0u8; 32];

        for entry in self.entries.iter() {
            let computed = AuditEntry::compute_hash(
                entry.timestamp,
                &entry.action,
                entry.target.as_deref(),
                prev,
            );
            if entry.entry_hash != computed {
                return false;
            }
            prev = entry.entry_hash;
        }

        true
    }

    pub fn entries(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log() {
        let mut log = AuditLog::new();

        log.log(AuditAction::SessionStart, Some("session-123".to_string()));
        log.log(AuditAction::ToolExecute, Some("read".to_string()));

        assert_eq!(log.len(), 2);
        assert!(log.verify());
    }

    #[test]
    fn test_audit_empty_verify() {
        let log = AuditLog::new();
        assert!(log.verify());
    }
}
