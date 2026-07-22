//! NSJail wrapper — launches commands inside NSJail with security profiles.
//!
//! NSJail provides user namespace + mount namespace + PID namespace isolation
//! with seccomp BPF filtering, cgroup resource limits, and configurable filesystem
//! jail via pivot_root/tmpfs.
//!
//! Falls back to native Landlock + Seccomp if NSJail is not installed.

use kraken_errors::SandboxError;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// NSJail configuration profile.
#[derive(Debug, Clone)]
pub struct NsJailProfile {
    pub name: String,
    pub chroot_dir: Option<PathBuf>,
    pub tmpfs_size_mb: u32,
    pub max_cpus: u32,
    pub max_memory_mb: u32,
    pub time_limit_secs: u32,
    pub wall_time_limit_secs: u32,
    pub max_procs: u32,
    pub read_write_paths: Vec<PathBuf>,
    pub read_only_paths: Vec<PathBuf>,
    pub is_root: bool,
    pub disable_network: bool,
    pub seccomp_string: Option<String>,
    pub cgroup_mem_mb: Option<u32>,
    pub cgroup_cpu_quota: Option<u32>,
}

impl Default for NsJailProfile {
    fn default() -> Self {
        Self {
            name: "opencode".to_string(),
            chroot_dir: None,
            tmpfs_size_mb: 64,
            max_cpus: 1,
            max_memory_mb: 1024,
            time_limit_secs: 60,
            wall_time_limit_secs: 65,
            max_procs: 16,
            read_write_paths: Vec::new(),
            read_only_paths: Vec::new(),
            is_root: false,
            disable_network: true,
            seccomp_string: None,
            cgroup_mem_mb: None,
            cgroup_cpu_quota: None,
        }
    }
}

impl NsJailProfile {
    pub fn to_config_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("name: '{}';", self.name));

        if let Some(ref chroot) = self.chroot_dir {
            lines.push(format!("chroot: '{}';", chroot.display()));
        } else {
            lines.push("chroot: '/'".to_string());
        }

        lines.push(format!("tmpfs: '/tmp' size={}m;", self.tmpfs_size_mb));
        lines.push(format!("max_cpus: {};", self.max_cpus));
        lines.push(format!(
            "max_mem: '{}m';",
            self.max_memory_mb
        ));
        lines.push(format!("time_limit: '{}';", self.time_limit_secs));
        lines.push(format!("wall_time_limit: '{}';", self.wall_time_limit_secs));
        lines.push(format!("max_procs: {};", self.max_procs));

        for path in &self.read_write_paths {
            lines.push(format!("bind: '{}' rw;", path.display()));
        }
        for path in &self.read_only_paths {
            lines.push(format!("bind: '{}' ro;", path.display()));
        }

        if !self.is_root {
            lines.push("is_root: false;".to_string());
        }

        if self.disable_network {
            lines.push("iface: 'lo';".to_string());
            lines.push("iface_no_lo: false;".to_string());
        }

        if let Some(ref seccomp) = self.seccomp_string {
            lines.push(format!("seccomp_string: '{}';", seccomp));
        }

        if let Some(mem) = self.cgroup_mem_mb {
            lines.push(format!("cgroup_mem_max: '{}';", mem));
        }
        if let Some(cpu) = self.cgroup_cpu_quota {
            lines.push(format!("cgroup_cpu_ms_per_sec: {};", cpu));
        }

        lines
    }
}

/// Check if NSJail is available on the system.
pub fn nsjail_available() -> bool {
    which_nsjail().is_some()
}

fn which_nsjail() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("nsjail");
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

/// Result of an NSJail execution.
#[derive(Debug, Clone)]
pub struct NsJailResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub wall_time_ms: u64,
    pub cpu_time_ms: u64,
    pub peak_mem_kb: u64,
}

/// Launch a command inside NSJail.
pub fn execute_nsjail(
    profile: &NsJailProfile,
    program: &str,
    args: &[&str],
    env: &HashMap<String, String>,
) -> Result<NsJailResult, SandboxError> {
    let nsjail_path = which_nsjail().ok_or_else(|| SandboxError::NsJail("NSJail not found in PATH".to_string()))?;

    let config = profile.to_config_lines().join("\n");
    let config_path = std::env::temp_dir().join(format!("nsjail_{}.cfg", std::process::id()));
    std::fs::write(&config_path, &config)
        .map_err(|e| SandboxError::NsJail(format!("cannot write nsjail config: {e}")))?;

    let mut cmd = Command::new(&nsjail_path);
    cmd.args([
        "--config",
        config_path.to_str().unwrap_or(""),
        "--",
        program,
    ]);
    for arg in args {
        cmd.arg(arg);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let start = std::time::Instant::now();
    let output = cmd
        .output()
        .map_err(SandboxError::Io)?;
    let elapsed = start.elapsed();

    let _ = std::fs::remove_file(&config_path);

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(NsJailResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: stdout_str,
        stderr: stderr_str,
        wall_time_ms: elapsed.as_millis() as u64,
        cpu_time_ms: 0,
        peak_mem_kb: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsjail_profile_default() {
        let profile = NsJailProfile::default();
        assert_eq!(profile.name, "opencode");
        assert!(profile.disable_network);
        assert_eq!(profile.time_limit_secs, 60);
    }

    #[test]
    fn test_nsjail_profile_config_lines() {
        let profile = NsJailProfile::default();
        let lines = profile.to_config_lines();
        assert!(lines.iter().any(|l| l.contains("name:")));
        assert!(lines.iter().any(|l| l.contains("time_limit:")));
        assert!(lines.iter().any(|l| l.contains("max_cpus:")));
    }

    #[test]
    fn test_nsjail_profile_with_paths() {
        let mut profile = NsJailProfile::default();
        profile.read_write_paths.push(PathBuf::from("/tmp/work"));
        profile.read_only_paths.push(PathBuf::from("/usr/bin"));
        let lines = profile.to_config_lines();
        assert!(lines.iter().any(|l| l.contains("bind: '/tmp/work' rw")));
        assert!(lines.iter().any(|l| l.contains("bind: '/usr/bin' ro")));
    }

    #[test]
    fn test_nsjail_profile_cgroup() {
        let mut profile = NsJailProfile::default();
        profile.cgroup_mem_mb = Some(256);
        profile.cgroup_cpu_quota = Some(500);
        let lines = profile.to_config_lines();
        assert!(lines.iter().any(|l| l.contains("cgroup_mem_max:")));
        assert!(lines.iter().any(|l| l.contains("cgroup_cpu_ms_per_sec:")));
    }

    #[test]
    fn test_nsjail_available() {
        // This test checks if nsjail is available on the system.
        // It's informational — no assertion on result.
        let available = nsjail_available();
        eprintln!("NSJail available: {available}");
    }

    #[test]
    fn test_nsjail_execute_not_found() {
        let profile = NsJailProfile::default();
        let env = HashMap::new();
        let result = execute_nsjail(&profile, "echo", &["hello"], &env);
        // May fail if nsjail not installed — that's expected
        if let Err(ref e) = result {
            assert!(e.to_string().contains("not found"));
        }
    }
}
