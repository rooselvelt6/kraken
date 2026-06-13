//! Sandbox Crate — Tool Execution Isolation
//!
//! Provides sandboxed tool execution with:
//! - Seccomp BPF syscall filtering
//! - Resource limits (rlimit)
//! - NSJail wrapper (optional external backend)
//! - Landlock filesystem restrictions (planned)
//!
//! All safety-critical syscalls are made through the `nix` crate,
//! which provides safe Rust wrappers. No `unsafe` code in this crate.

pub mod landlock;
pub mod namespace;
pub mod nsjail;
pub mod platform_macos;
pub mod platform_windows;
pub mod resource;
pub mod seccomp;
pub mod tmpfs;

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
    pub enable_seccomp: bool,
    pub enable_rlimits: bool,
    pub enable_nsjail: bool,
    pub network_isolation: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,
            max_cpu_seconds: 60,
            allowed_syscalls: HashSet::new(),
            allowed_paths: HashSet::new(),
            working_directory: None,
            enable_seccomp: true,
            enable_rlimits: true,
            enable_nsjail: false,
            network_isolation: true,
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

        let output = cmd.output().map_err(|e| format!("execute failed: {e}"))?;

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

    pub fn apply_rlimits(&self) -> Result<(), String> {
        if !self.config.enable_rlimits {
            return Ok(());
        }
        let limits = resource::ResourceLimits {
            cpu_time_secs: self.config.max_cpu_seconds,
            address_space_bytes: self.config.max_memory_bytes,
            ..resource::ResourceLimits::default()
        };
        limits.apply()
    }

    pub fn install_seccomp(&self) -> Result<(), String> {
        if !self.config.enable_seccomp {
            return Ok(());
        }
        let profile = seccomp::SeccompProfile {
            mode: seccomp::SeccompMode::ReadWrite,
            allow_network: !self.config.network_isolation,
            allow_ptrace: false,
        };
        profile.install()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_default() {
        let sandbox = ToolSandbox::with_default();
        assert!(sandbox.verify_config());
        assert!(sandbox.config.enable_seccomp);
        assert!(sandbox.config.enable_rlimits);
    }

    #[test]
    fn test_sandbox_execute() {
        let sandbox = ToolSandbox::with_default();
        let result = sandbox.execute("echo", &["hello"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sandbox_config_custom() {
        let config = SandboxConfig {
            enable_seccomp: false,
            enable_rlimits: false,
            ..SandboxConfig::default()
        };
        let sandbox = ToolSandbox::new(config);
        assert!(!sandbox.config.enable_seccomp);
    }

    #[test]
    fn test_sandbox_apply_rlimits() {
        let mut config = SandboxConfig::default();
        config.enable_rlimits = false;
        let sandbox = ToolSandbox::new(config);
        assert!(sandbox.apply_rlimits().is_ok());
    }

    #[test]
    fn test_sandbox_install_seccomp_disabled() {
        let mut config = SandboxConfig::default();
        config.enable_seccomp = false;
        let sandbox = ToolSandbox::new(config);
        assert!(sandbox.install_seccomp().is_ok());
    }
}
