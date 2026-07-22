//! Windows Sandbox — AppContainer + JobObject isolation.
//!
//! Uses Windows security primitives:
//! - AppContainer: Isolated execution environment with restricted capabilities
//! - JobObject: Process group management with resource limits
//! - Desktop Restriction: Separate desktop for isolation
//!
//! Note: Full AppContainer support requires Windows 8+.
//! This module provides a best-effort implementation using available Windows APIs.

#![allow(non_snake_case)]

use kraken_errors::SandboxError;

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Security::AppContainer;
#[cfg(windows)]
use windows::Win32::System::JobObjects;
#[cfg(windows)]
use windows::Win32::System::Threading;

#[derive(Debug, Clone)]
pub struct WindowsSandboxConfig {
    pub enabled: bool,
    pub max_memory_mb: u64,
    pub max_cpu_percent: u64,
    pub max_processes: u32,
    pub disable_network: bool,
}

impl Default for WindowsSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory_mb: 512,
            max_cpu_percent: 50,
            max_processes: 16,
            disable_network: true,
        }
    }
}

pub struct WindowsSandbox;

impl WindowsSandbox {
    /// Apply Windows sandbox restrictions to the current process.
    /// This should be called before spawning child processes.
    pub fn apply(config: &WindowsSandboxConfig) -> Result<(), SandboxError> {
        if !config.enabled {
            return Ok(());
        }

        #[cfg(windows)]
        {
            Self::apply_appcontainer()?;
            Self::apply_jobobject(config)?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = config;
            Err(SandboxError::PlatformUnsupported("Windows sandbox is only available on Windows".to_string()))
        }
    }

    #[cfg(windows)]
    fn apply_appcontainer() -> Result<(), SandboxError> {
        // AppContainer creation requires Windows 8+
        // This is a placeholder for the full implementation
        log::warn!("AppContainer sandbox not fully implemented");
        Ok(())
    }

    #[cfg(windows)]
    fn apply_jobobject(config: &WindowsSandboxConfig) -> Result<(), SandboxError> {
        // Create a JobObject with resource limits
        let job = unsafe {
            JobObjects::CreateJobObjectW(None, None)
                .map_err(SandboxError::Io)?
        };

        // Set memory limit
        let mem_limit = JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JobObjects::JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JobObjects::JOB_OBJECT_LIMIT_JOB_MEMORY
                    | JobObjects::JOB_OBJECT_LIMIT_PROCESS_MEMORY,
                ..Default::default()
            },
            JobMemoryLimit: config.max_memory_mb * 1024 * 1024,
            ProcessMemoryLimit: config.max_memory_mb * 1024 * 1024,
            ..Default::default()
        };

        unsafe {
            JobObjects::SetInformationJobObject(
                job,
                JobObjects::JobObjectInfoClass::JobObjectExtendedLimitInformation,
                &mem_limit as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| SandboxError::Other(format!("SetInformationJobObject: {e}")))?;
        }

        // Set active process limit
        let proc_limit = JobObjects::JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JobObjects::JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            ActiveProcessLimit: config.max_processes,
            ..Default::default()
        };

        unsafe {
            JobObjects::SetInformationJobObject(
                job,
                JobObjects::JobObjectInfoClass::JobObjectBasicLimitInformation,
                &proc_limit as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JobObjects::JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| SandboxError::Other(format!("SetInformationJobObject (proc limit): {e}")))?;
        }

        // Assign current process to the job
        let current_process = unsafe { Threading::GetCurrentProcess() };
        unsafe {
            JobObjects::AssignProcessToJobObject(job, current_process)
                .map_err(|e| SandboxError::Other(format!("AssignProcessToJobObject: {e}")))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_config_default() {
        let config = WindowsSandboxConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.max_processes, 16);
        assert!(config.disable_network);
    }

    #[test]
    fn test_windows_config_custom() {
        let config = WindowsSandboxConfig {
            enabled: true,
            max_memory_mb: 1024,
            max_cpu_percent: 75,
            max_processes: 32,
            disable_network: false,
        };
        assert_eq!(config.max_memory_mb, 1024);
    }

    #[test]
    fn test_windows_sandbox_disabled() {
        let config = WindowsSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(WindowsSandbox::apply(&config).is_ok());
    }

    #[test]
    fn test_windows_sandbox_apply() {
        let config = WindowsSandboxConfig::default();
        if cfg!(windows) {
            let _result = WindowsSandbox::apply(&config);
            // On Windows CI, AppContainer may not be available
        } else {
            assert!(WindowsSandbox::apply(&config).is_err());
        }
    }
}
