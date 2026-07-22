use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolKind {
    Read,
    Write,
    Edit,
    Glob,
    Grep,
    Bash,
    Other,
}

impl ToolKind {
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "read_file" | "Read" => Self::Read,
            "write_file" | "Write" => Self::Write,
            "edit_file" | "Edit" => Self::Edit,
            "glob_search" | "GlobSearch" | "glob" => Self::Glob,
            "grep_search" | "GrepSearch" | "grep" => Self::Grep,
            "bash" | "Bash" => Self::Bash,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolBudget {
    pub max_bytes: u64,
    pub max_entries: Option<usize>,
    pub max_calls: u32,
    pub window_secs: u64,
}

impl ToolBudget {
    #[must_use]
    pub fn for_read() -> Self {
        Self { max_bytes: 10 * 1024 * 1024, max_entries: None, max_calls: 200, window_secs: 300 }
    }
    #[must_use]
    pub fn for_write() -> Self {
        Self { max_bytes: 5 * 1024 * 1024, max_entries: None, max_calls: 100, window_secs: 300 }
    }
    #[must_use]
    pub fn for_glob() -> Self {
        Self { max_bytes: 1024 * 1024, max_entries: Some(1000), max_calls: 50, window_secs: 300 }
    }
    #[must_use]
    pub fn for_grep() -> Self {
        Self { max_bytes: 1024 * 1024, max_entries: None, max_calls: 100, window_secs: 300 }
    }
    #[must_use]
    pub fn for_bash() -> Self {
        Self { max_bytes: 10 * 1024 * 1024, max_entries: None, max_calls: 100, window_secs: 300 }
    }
    #[must_use]
    pub fn for_edit() -> Self {
        Self { max_bytes: 5 * 1024 * 1024, max_entries: None, max_calls: 100, window_secs: 300 }
    }
}

#[derive(Debug, Clone)]
struct ToolCallRecord {
    timestamp: Instant,
    bytes_processed: u64,
}

#[derive(Debug, Clone)]
struct ToolUsage {
    budget: ToolBudget,
    records: Vec<ToolCallRecord>,
}

impl ToolUsage {
    fn new(budget: ToolBudget) -> Self {
        Self { budget, records: Vec::new() }
    }

    fn prune(&mut self) {
        let cutoff = Instant::now().checked_sub(Duration::from_secs(self.budget.window_secs)).unwrap();
        self.records.retain(|r| r.timestamp > cutoff);
    }

    fn call_count(&mut self) -> u32 {
        self.prune();
        #[allow(clippy::cast_possible_truncation)]
        { self.records.len() as u32 }
    }

    fn total_bytes(&mut self) -> u64 {
        self.prune();
        self.records.iter().map(|r| r.bytes_processed).sum()
    }
}

#[derive(Debug)]
pub struct SizeBudgeter {
    per_tool: HashMap<ToolKind, ToolUsage>,
    session_calls: u64,
    session_bytes: u64,
}

impl SizeBudgeter {
    #[must_use]
    pub fn new() -> Self {
        let mut per_tool = HashMap::new();
        per_tool.insert(ToolKind::Read, ToolUsage::new(ToolBudget::for_read()));
        per_tool.insert(ToolKind::Write, ToolUsage::new(ToolBudget::for_write()));
        per_tool.insert(ToolKind::Edit, ToolUsage::new(ToolBudget::for_edit()));
        per_tool.insert(ToolKind::Glob, ToolUsage::new(ToolBudget::for_glob()));
        per_tool.insert(ToolKind::Grep, ToolUsage::new(ToolBudget::for_grep()));
        per_tool.insert(ToolKind::Bash, ToolUsage::new(ToolBudget::for_bash()));
        Self { per_tool, session_calls: 0, session_bytes: 0 }
    }

    pub fn check_tool_call(&mut self, tool: ToolKind, bytes: u64) -> Result<(), BudgetExceeded> {
        self.session_calls += 1;
        self.session_bytes += bytes;

        if self.session_calls > 5000 {
            return Err(BudgetExceeded::SessionCalls(self.session_calls));
        }
        if self.session_bytes > 200 * 1024 * 1024 {
            return Err(BudgetExceeded::SessionBytes(self.session_bytes));
        }

        self.per_tool.entry(tool).or_insert_with(|| ToolUsage::new(ToolBudget {
                max_bytes: 10 * 1024 * 1024,
                max_entries: None,
                max_calls: 1000,
                window_secs: 300,
            }));
        let usage = self.per_tool.get_mut(&tool).expect("tool just inserted");

        let count = usage.call_count();
        if count >= usage.budget.max_calls {
            return Err(BudgetExceeded::ToolCalls { tool, count, limit: usage.budget.max_calls });
        }

        let total = usage.total_bytes() + bytes;
        if total > usage.budget.max_bytes {
            return Err(BudgetExceeded::ToolBytes { tool, bytes: total, limit: usage.budget.max_bytes });
        }

        usage.records.push(ToolCallRecord {
            timestamp: Instant::now(),
            bytes_processed: bytes,
        });

        Ok(())
    }

    pub fn check_read(&mut self, bytes: u64) -> Result<(), BudgetExceeded> {
        self.check_tool_call(ToolKind::Read, bytes)
    }

    pub fn check_write(&mut self, bytes: u64) -> Result<(), BudgetExceeded> {
        self.check_tool_call(ToolKind::Write, bytes)
    }

    pub fn check_glob(&mut self, entries: usize) -> Result<(), BudgetExceeded> {
        self.check_tool_call(ToolKind::Glob, entries as u64 /* approximated */)
    }

    pub fn check_grep(&mut self, bytes: u64) -> Result<(), BudgetExceeded> {
        self.check_tool_call(ToolKind::Grep, bytes)
    }

    pub fn check_bash(&mut self) -> Result<(), BudgetExceeded> {
        self.check_tool_call(ToolKind::Bash, 0)
    }

    #[must_use]
    pub fn session_statistics(&self) -> SessionStats {
        SessionStats {
            total_calls: self.session_calls,
            total_bytes: self.session_bytes,
        }
    }
}

impl Default for SizeBudgeter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub total_calls: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub enum BudgetExceeded {
    ToolCalls { tool: ToolKind, count: u32, limit: u32 },
    ToolBytes { tool: ToolKind, bytes: u64, limit: u64 },
    SessionCalls(u64),
    SessionBytes(u64),
}

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolCalls { tool, count, limit } => {
                write!(f, "{tool:?} call limit {limit} exceeded: {count}")
            }
            Self::ToolBytes { tool, bytes, limit } => {
                write!(f, "{tool:?} byte limit {limit} exceeded: {bytes}")
            }
            Self::SessionCalls(calls) => {
                write!(f, "session call limit 5000 exceeded: {calls}")
            }
            Self::SessionBytes(bytes) => {
                write!(f, "session byte limit 200MB exceeded: {bytes}")
            }
        }
    }
}

impl std::error::Error for BudgetExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_budget_allows_normal_usage() {
        let mut b = SizeBudgeter::new();
        assert!(b.check_read(1024).is_ok());
        assert!(b.check_read(4096).is_ok());
    }

    #[test]
    fn read_budget_exceeds_calls() {
        let mut b = SizeBudgeter::new();
        for _ in 0..200 {
            assert!(b.check_read(1).is_ok());
        }
        assert!(b.check_read(1).is_err());
    }

    #[test]
    fn write_budget_bytes() {
        let mut b = SizeBudgeter::new();
        assert!(b.check_write(2 * 1024 * 1024).is_ok());
        assert!(b.check_write(2 * 1024 * 1024).is_ok());
        assert!(b.check_write(2 * 1024 * 1024).is_err());
    }

    #[test]
    fn glob_budget_entries() {
        let mut b = SizeBudgeter::new();
        assert!(b.check_glob(100).is_ok());
        assert!(b.check_glob(100).is_ok());
    }

    #[test]
    fn session_budget() {
        let mut b = SizeBudgeter::new();
        // Bash has max_calls=100, so we hit session limit before tool limit
        for i in 0..100 {
            assert!(b.check_tool_call(ToolKind::Bash, 1).is_ok(), "iteration {i}");
        }
    }

    #[test]
    fn tool_kind_from_name() {
        assert_eq!(ToolKind::from_name("read_file"), ToolKind::Read);
        assert_eq!(ToolKind::from_name("bash"), ToolKind::Bash);
        assert_eq!(ToolKind::from_name("unknown"), ToolKind::Other);
    }

    #[test]
    fn statistics_tracked() {
        let mut b = SizeBudgeter::new();
        b.check_read(100).unwrap();
        b.check_write(200).unwrap();
        let stats = b.session_statistics();
        assert_eq!(stats.total_calls, 2);
        assert_eq!(stats.total_bytes, 300);
    }
}
