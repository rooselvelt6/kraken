//! Sandbox Crate - Tool Execution Isolation
//!
//! Provides sandboxed tool execution with syscall whitelisting and memory limits.
//! Currently a placeholder for future seccomp/wasmer integration.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub max_memory_bytes: u64,
    pub max_cpu_seconds: u64,
    pub allowed_syscalls: HashSet<String>,
    pub allowed_paths: HashSet<PathBuf>,
    pub working_directory: Option<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,
            max_cpu_seconds: 60,
            allowed_syscalls: HashSet::new(),
            allowed_paths: HashSet::new(),
            working_directory: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxResult {
    Success,
    MemoryLimit,
    CpuLimit,
    SyscallDenied,
    PathDenied,
    Timeout,
    Error,
}

pub struct ToolSandbox {
    config: SandboxConfig,
}

impl ToolSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(SandboxConfig::default())
    }

    pub fn execute(&self, program: &str, args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        if let Some(ref dir) = self.config.working_directory {
            cmd.current_dir(dir);
        }

        let output = cmd.output().map_err(|e| format!("execute failed: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    pub fn can_execute(&self, _program: &str) -> bool {
        true
    }

    pub fn verify_config(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_default() {
        let sandbox = ToolSandbox::with_default();
        assert!(sandbox.verify_config());
    }

    #[test]
    fn test_sandbox_execute() {
        let sandbox = ToolSandbox::with_default();
        let result = sandbox.execute("echo", &["hello"]);
        assert!(result.is_ok());
    }
}
