use crate::{DiscoveryMethod, ExploitType, Finding, Severity};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CrashType {
    UseAfterFree,
    OutOfBoundsRead,
    OutOfBoundsWrite,
    DoubleFree,
    DataRace,
    NullPointerDeref,
    StackOverflow,
    InfoLeak,
    Rop,
    UninitMemory,
    KernelPanic,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CrashSignature {
    pub hash: String,
    pub crash_type: CrashType,
    pub symptom: String,
    pub backtrace_frames: Vec<String>,
}

impl CrashSignature {
    /// Parses a crash signature from dmesg output.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::fuzz::CrashSignature;
    /// let sig = CrashSignature::from_dmesg(
    ///     "BUG: KASAN: use-after-free in kfree+0x100/0x200\n\
    ///      Call Trace:\n\
    ///      kfree+0x100/0x200\n\
    ///      my_func+0x50/0x100\n"
    /// ).unwrap();
    /// assert_eq!(sig.crash_type, vulnscan::kernel::fuzz::CrashType::UseAfterFree);
    /// assert_eq!(sig.backtrace_frames.len(), 2);
    /// ```
    pub fn from_dmesg(dmesg: &str) -> Option<Self> {
        let crash_type = Self::classify_crash(dmesg);
        let symptom = Self::extract_symptom(dmesg);
        let frames = Self::extract_backtrace(dmesg);
        let hash = Self::hash_backtrace(&frames);

        Some(CrashSignature {
            hash,
            crash_type,
            symptom,
            backtrace_frames: frames,
        })
    }

    fn classify_crash(dmesg: &str) -> CrashType {
        let lower = dmesg.to_lowercase();
        if lower.contains("bug: kasan:") {
            if lower.contains("use-after-free") {
                CrashType::UseAfterFree
            } else if lower.contains("out-of-bounds") {
                if lower.contains("write") {
                    CrashType::OutOfBoundsWrite
                } else {
                    CrashType::OutOfBoundsRead
                }
            } else if lower.contains("double-free") {
                CrashType::DoubleFree
            } else if lower.contains("wild-memory-access") {
                CrashType::NullPointerDeref
            } else {
                CrashType::Unknown
            }
        } else if lower.contains("bug: kcsan:") {
            CrashType::DataRace
        } else if lower.contains("bug: kmsan:") {
            CrashType::UninitMemory
        } else if lower.contains("kernel panic") || lower.contains("kernel BUG at") {
            if lower.contains("stack smashing detected") {
                CrashType::StackOverflow
            } else {
                CrashType::KernelPanic
            }
        } else if lower.contains("general protection fault")
            || lower.contains("page fault")
            || lower.contains("segfault")
        {
            CrashType::NullPointerDeref
        } else if lower.contains("rip:") || lower.contains("eip:") || lower.contains("pc :") {
            CrashType::Rop
        } else {
            CrashType::Unknown
        }
    }

    fn extract_symptom(dmesg: &str) -> String {
        for line in dmesg.lines() {
            if line.contains("BUG:")
                || line.contains("KASAN:")
                || line.contains("KCSAN:")
                || line.contains("KMSAN:")
                || line.contains("kernel panic")
            {
                return line.trim().to_string();
            }
        }
        dmesg.lines().next().unwrap_or("unknown crash").to_string()
    }

    fn extract_backtrace(dmesg: &str) -> Vec<String> {
        let mut frames = Vec::new();
        let mut in_trace = false;

        for line in dmesg.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Call Trace:") || trimmed.starts_with("Backtrace:") {
                in_trace = true;
                continue;
            }
            if in_trace {
                if trimmed.is_empty() || trimmed.starts_with("---[") {
                    in_trace = false;
                } else if trimmed.contains("0x") || trimmed.contains("<") {
                    frames.push(trimmed.to_string());
                }
            }
        }

        frames
    }

    fn hash_backtrace(frames: &[String]) -> String {
        let mut hasher = Sha256::new();
        for frame in frames {
            hasher.update(frame.as_bytes());
            hasher.update(b"\n");
        }
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CrashEntry {
    pub signature: CrashSignature,
    pub input_path: Option<PathBuf>,
    pub dmesg_log: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub fuzzer: String,
}

#[derive(Debug, Clone)]
pub struct TriageReport {
    pub total_crashes: usize,
    pub unique_crashes: usize,
    pub cwe_counts: HashMap<String, usize>,
    pub crash_type_counts: HashMap<String, usize>,
    pub findings: Vec<Finding>,
}

pub struct CrashTriage {
    crashes: Vec<CrashEntry>,
    seen_hashes: HashMap<String, usize>,
}

impl Default for CrashTriage {
    fn default() -> Self {
        Self::new()
    }
}

impl CrashTriage {
    /// Creates a new empty crash triage system.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::fuzz::CrashTriage;
    /// let mut triage = CrashTriage::new();
    /// let report = triage.triage();
    /// assert_eq!(report.total_crashes, 0);
    /// assert_eq!(report.unique_crashes, 0);
    /// ```
    pub fn new() -> Self {
        CrashTriage {
            crashes: Vec::new(),
            seen_hashes: HashMap::new(),
        }
    }

    pub fn add_crash(&mut self, entry: CrashEntry) {
        let hash = entry.signature.hash.clone();
        *self.seen_hashes.entry(hash).or_insert(0) += 1;
        self.crashes.push(entry);
    }

    pub fn deduplicate(&self) -> Vec<&CrashEntry> {
        let mut seen = HashMap::new();
        let mut unique = Vec::new();

        for entry in &self.crashes {
            if !seen.contains_key(&entry.signature.hash) {
                seen.insert(entry.signature.hash.clone(), true);
                unique.push(entry);
            }
        }

        unique
    }

    pub fn triage(&self) -> TriageReport {
        let unique = self.deduplicate();
        let mut cwe_counts = HashMap::new();
        let mut crash_type_counts = HashMap::new();
        let mut findings = Vec::new();

        for entry in &unique {
            let (cwe, severity) = assign_cwe(&entry.signature.crash_type);
            *cwe_counts.entry(cwe.clone()).or_insert(0) += 1;
            *crash_type_counts
                .entry(format!("{:?}", entry.signature.crash_type))
                .or_insert(0) += 1;

            let finding = Finding {
                id: crate::new_finding_id(),
                severity,
                cwe: Some(cwe),
                cve: None,
                description: format!(
                    "Fuzzing crash: {} — {:?} ({} occurrences)",
                    entry.signature.symptom,
                    entry.signature.crash_type,
                    self.seen_hashes.get(&entry.signature.hash).unwrap_or(&1)
                ),
                file_path: entry.input_path.clone(),
                line_number: None,
                vulnerable_code_snippet: entry.signature.backtrace_frames.first().cloned(),
                remediation: Some(remediation_for_crash(&entry.signature.crash_type)),
                confidence: 0.85,
                discovery_method: DiscoveryMethod::Fuzzing,
                exploit_code: None,
                exploit_type: None,
                chained_findings: vec![],
                poc_validated: false,
                status: crate::FindingStatus::Open,
                cvss_score: Some(match severity {
                    Severity::Critical => 9.0,
                    Severity::High => 7.5,
                    Severity::Medium => 5.0,
                    _ => 3.0,
                }),
                severity_confidence: 0.85,
                discovered_at: chrono::Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            };

            findings.push(finding);
        }

        TriageReport {
            total_crashes: self.crashes.len(),
            unique_crashes: unique.len(),
            cwe_counts,
            crash_type_counts,
            findings,
        }
    }
}

/// Maps a crash type to its corresponding CWE and severity.
///
/// # Examples
///
/// ```
/// use vulnscan::kernel::fuzz::{assign_cwe, CrashType};
/// use vulnscan::Severity;
/// let (cwe, sev) = assign_cwe(&CrashType::UseAfterFree);
/// assert_eq!(cwe, "CWE-416");
/// assert_eq!(sev, Severity::Critical);
/// let (cwe, _) = assign_cwe(&CrashType::DataRace);
/// assert_eq!(cwe, "CWE-362");
/// ```
pub fn assign_cwe(crash_type: &CrashType) -> (String, Severity) {
    match crash_type {
        CrashType::UseAfterFree => ("CWE-416".to_string(), Severity::Critical),
        CrashType::OutOfBoundsRead => ("CWE-125".to_string(), Severity::High),
        CrashType::OutOfBoundsWrite => ("CWE-787".to_string(), Severity::Critical),
        CrashType::DoubleFree => ("CWE-415".to_string(), Severity::Critical),
        CrashType::DataRace => ("CWE-362".to_string(), Severity::High),
        CrashType::NullPointerDeref => ("CWE-476".to_string(), Severity::High),
        CrashType::StackOverflow => ("CWE-121".to_string(), Severity::Critical),
        CrashType::InfoLeak => ("CWE-200".to_string(), Severity::High),
        CrashType::Rop => ("CWE-269".to_string(), Severity::Critical),
        CrashType::UninitMemory => ("CWE-457".to_string(), Severity::Medium),
        CrashType::KernelPanic => ("CWE-20".to_string(), Severity::High),
        CrashType::Unknown => ("CWE-119".to_string(), Severity::Medium),
    }
}

fn remediation_for_crash(crash_type: &CrashType) -> String {
    match crash_type {
        CrashType::UseAfterFree => "Use-after-free detected. Ensure pointers are not used after kfree(). Set to NULL after freeing.".to_string(),
        CrashType::OutOfBoundsRead => "Out-of-bounds read detected. Validate array indices and buffer sizes before access.".to_string(),
        CrashType::OutOfBoundsWrite => "Out-of-bounds write detected. Validate buffer boundaries before writing. Use safe copy functions.".to_string(),
        CrashType::DoubleFree => "Double-free detected. Ensure kfree() is called only once. Set pointer to NULL after first free.".to_string(),
        CrashType::DataRace => "Data race detected. Add proper synchronization (mutex, spinlock, RCU) to protect shared data.".to_string(),
        CrashType::NullPointerDeref => "Null pointer dereference detected. Validate pointers before dereferencing.".to_string(),
        CrashType::StackOverflow => "Stack overflow detected. Reduce stack usage or increase stack size. Avoid deep recursion in kernel.".to_string(),
        CrashType::InfoLeak => "Information leak detected. Ensure sensitive kernel data is not exposed to userspace.".to_string(),
        CrashType::Rop => "Potential ROP chain detected. Review control flow integrity and kernel hardening options.".to_string(),
        CrashType::UninitMemory => "Uninitialized memory usage detected. Ensure all variables are initialized before use.".to_string(),
        CrashType::KernelPanic => "Kernel panic triggered. Review the crash log for the root cause and fix the triggering condition.".to_string(),
        CrashType::Unknown => "Unknown crash type. Review dmesg output for details.".to_string(),
    }
}

pub struct SyzkallerConfig {
    pub workdir: PathBuf,
    pub kernel_image: PathBuf,
    pub arch: String,
    pub cpus: usize,
    pub memory_mb: usize,
    pub timeout_secs: u64,
    pub targets: Vec<String>,
}

impl Default for SyzkallerConfig {
    fn default() -> Self {
        SyzkallerConfig {
            workdir: PathBuf::from("/tmp/kraken-syzkaller"),
            kernel_image: PathBuf::from("/boot/vmlinuz"),
            arch: "amd64".to_string(),
            cpus: 4,
            memory_mb: 4096,
            timeout_secs: 3600,
            targets: Vec::new(),
        }
    }
}

pub struct SyzkallerRunner;

impl SyzkallerRunner {
    pub fn generate_config(config: &SyzkallerConfig) -> String {
        format!(
            r#"{{
    "target": "{arch}-full",
    "workdir": "{workdir}",
    "kernel": "{kernel}",
    "syzkaller": "{workdir}/gopath/src/syzkaller",
    "procs": {cpus},
    "type": "qemu",
    "vm": {{
        "count": 1,
        "cpu": {cpus},
        "mem": {memory_mb}
    }},
    "cover": true,
    "collide": true,
    "threaded": false,
    "strength": false,
    "slowdown": 1,
    "raw_cover": false,
    "sandbox": "sandbox/namespace",
    "reproduce": true,
    "trace": true,
    "auto_start": false
}}"#,
            arch = config.arch,
            workdir = config.workdir.display(),
            kernel = config.kernel_image.display(),
            cpus = config.cpus,
            memory_mb = config.memory_mb,
        )
    }

    pub fn run(config: &SyzkallerConfig) -> Result<Vec<CrashEntry>, String> {
        let cfg_path = config.workdir.join("syzkaller.cfg");
        let cfg_content = Self::generate_config(config);

        std::fs::create_dir_all(&config.workdir)
            .map_err(|e| format!("Failed to create workdir: {e}"))?;
        std::fs::write(&cfg_path, &cfg_content)
            .map_err(|e| format!("Failed to write config: {e}"))?;

        let output = std::process::Command::new("syz-manager")
            .arg("-config")
            .arg(&cfg_path)
            .arg("-timeout")
            .arg(format!("{}s", config.timeout_secs))
            .current_dir(&config.workdir)
            .output()
            .map_err(|e| format!("Failed to run syz-manager: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[syzkaller] stderr: {stderr}");
        }

        Self::collect_crashes(config)
    }

    pub fn collect_crashes(config: &SyzkallerConfig) -> Result<Vec<CrashEntry>, String> {
        let mut crashes = Vec::new();
        let crash_dir = config.workdir.join("crashes");

        if !crash_dir.exists() {
            return Ok(crashes);
        }

        let entries = std::fs::read_dir(&crash_dir)
            .map_err(|e| format!("Failed to read crashes dir: {e}"))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dmesg_path = path.join("dmesg");
                if dmesg_path.exists() {
                    if let Ok(dmesg) = std::fs::read_to_string(&dmesg_path) {
                        if let Some(sig) = CrashSignature::from_dmesg(&dmesg) {
                            crashes.push(CrashEntry {
                                signature: sig,
                                input_path: Some(path.join("poc")),
                                dmesg_log: dmesg,
                                timestamp: chrono::Utc::now(),
                                fuzzer: "syzkaller".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(crashes)
    }
}

pub struct KaflConfig {
    pub workdir: PathBuf,
    pub kernel_image: PathBuf,
    pub ram_size: usize,
    pub shares_file: Option<PathBuf>,
    pub timeout_secs: u64,
    pub persistent: bool,
}

impl Default for KaflConfig {
    fn default() -> Self {
        KaflConfig {
            workdir: PathBuf::from("/tmp/kraken-kaf"),
            kernel_image: PathBuf::from("/boot/vmlinuz"),
            ram_size: 256,
            shares_file: None,
            timeout_secs: 3600,
            persistent: false,
        }
    }
}

pub struct KaflRunner;

impl KaflRunner {
    pub fn run(config: &KaflConfig) -> Result<Vec<CrashEntry>, String> {
        std::fs::create_dir_all(&config.workdir)
            .map_err(|e| format!("Failed to create workdir: {e}"))?;

        let mut args = vec![
            "fuzz".to_string(),
            "--workdir".to_string(),
            config.workdir.display().to_string(),
            "--ram-size".to_string(),
            config.ram_size.to_string(),
        ];

        if let Some(ref shares) = config.shares_file {
            args.push("--shares-file".to_string());
            args.push(shares.display().to_string());
        }

        if config.persistent {
            args.push("--persistent".to_string());
        }

        let output = std::process::Command::new("kafl")
            .args(&args)
            .current_dir(&config.workdir)
            .output()
            .map_err(|e| format!("Failed to run kafl: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[kafl] stderr: {stderr}");
        }

        Self::collect_crashes(config)
    }

    pub fn collect_crashes(config: &KaflConfig) -> Result<Vec<CrashEntry>, String> {
        let mut crashes = Vec::new();
        let crash_dir = config.workdir.join("crashes");

        if !crash_dir.exists() {
            return Ok(crashes);
        }

        let entries = std::fs::read_dir(&crash_dir)
            .map_err(|e| format!("Failed to read crashes dir: {e}"))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dmesg_path = path.join("dmesg.txt");
                if dmesg_path.exists() {
                    if let Ok(dmesg) = std::fs::read_to_string(&dmesg_path) {
                        if let Some(sig) = CrashSignature::from_dmesg(&dmesg) {
                            crashes.push(CrashEntry {
                                signature: sig,
                                input_path: Some(path.join("input")),
                                dmesg_log: dmesg,
                                timestamp: chrono::Utc::now(),
                                fuzzer: "kafl".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(crashes)
    }
}

pub fn generate_exploit_from_crash(
    crash: &CrashEntry,
    kernel_version: Option<&str>,
    arch: &str,
) -> Option<Finding> {
    match &crash.signature.crash_type {
        CrashType::UseAfterFree | CrashType::OutOfBoundsWrite | CrashType::DoubleFree => {
            let exploit_code = format!(
                r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * Auto-generated PoC for kernel crash: {}
 * Type: {:?}
 * Kernel: {}
 * Arch: {}
 *
 * WARNING: This is a template. Adjust addresses for your target kernel.
 */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void *prepare_kernel_cred_addr = 0;
static void *commit_creds_addr = 0;

static void payload(void) {{
    asm volatile(
        "xor %%rdi, %%rdi\n"
        "callq *%0\n"
        "movq %%rax, %%rdi\n"
        "callq *%1\n"
        :
        : "m"(prepare_kernel_cred_addr), "m"(commit_creds_addr)
        : "rdi", "rax"
    );
}}

int main(void) {{
    printf("[*] Kernel {{}} exploit PoC\n", "{{}}");
    printf("[*] Crash type: {{:?}}\n");
    printf("[!] TODO: Map kernel symbols from /proc/kallsyms\n");
    printf("[!] TODO: Trigger vulnerability\n");

    /* TODO: Implement actual trigger based on crash input */

    return 0;
}}
"#,
                crash.signature.symptom,
                format!("{:?}", crash.signature.crash_type),
                kernel_version.unwrap_or("unknown"),
                arch,
            );

            let cwe = assign_cwe(&crash.signature.crash_type).0;

            Some(Finding {
                id: crate::new_finding_id(),
                severity: Severity::Critical,
                cwe: Some(cwe),
                cve: None,
                description: format!(
                    "Exploit PoC generated from crash: {}",
                    crash.signature.symptom
                ),
                file_path: crash.input_path.clone(),
                line_number: None,
                vulnerable_code_snippet: Some(exploit_code.clone()),
                remediation: None,
                confidence: 0.70,
                discovery_method: DiscoveryMethod::Fuzzing,
                exploit_code: Some(exploit_code),
                exploit_type: Some(ExploitType::PrivilegeEscalation),
                chained_findings: vec![],
                poc_validated: false,
                status: crate::FindingStatus::InTriage,
                cvss_score: Some(9.5),
                severity_confidence: 0.70,
                discovered_at: chrono::Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            })
        }
        _ => None,
    }
}

pub fn minimize_input<F>(crash_input: &[u8], test_fn: F, max_iterations: usize) -> Vec<u8>
where
    F: Fn(&[u8]) -> bool,
{
    if !test_fn(crash_input) {
        return crash_input.to_vec();
    }

    let mut minimized = crash_input.to_vec();
    let mut changed = true;
    let mut iterations = 0;

    while changed && iterations < max_iterations {
        changed = false;
        iterations += 1;

        let mut i = 0;
        while i < minimized.len() {
            let mut try_remove = minimized.clone();
            try_remove.remove(i);

            if try_remove.is_empty() {
                i += 1;
                continue;
            }

            if test_fn(&try_remove) {
                minimized = try_remove;
                changed = true;
            } else {
                i += 1;
            }
        }

        if !changed {
            let chunk_size = minimized.len() / 2;
            if chunk_size > 0 {
                for start in (0..minimized.len()).step_by(chunk_size) {
                    let end = (start + chunk_size).min(minimized.len());
                    let mut try_reduce = minimized.clone();
                    for idx in (start..end).rev() {
                        try_reduce.remove(idx);
                    }
                    if test_fn(&try_reduce) {
                        minimized = try_reduce;
                        changed = true;
                        break;
                    }
                }
            }
        }
    }

    minimized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crash_signature_from_kasan_dmesg() {
        let dmesg = r#"BUG: KASAN: use-after-free in test_func+0x100/0x200
Read of size 4 at addr ffff888012345678 by task test/1234
CPU: 0 PID: 1234 Comm: test
Call Trace:
 test_func+0x100/0x200
 caller_func+0x50/0x100
"#;
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::UseAfterFree);
        assert!(sig.backtrace_frames.len() >= 2);
        assert!(!sig.hash.is_empty());
    }

    #[test]
    fn test_crash_signature_oob_write() {
        let dmesg = r#"BUG: KASAN: out-of-bounds write in vuln_func+0x50/0x100
Write of size 8 at addr ffff8880aabbccdd by task test/5678
Call Trace:
 vuln_func+0x50/0x100
"#;
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::OutOfBoundsWrite);
    }

    #[test]
    fn test_crash_signature_kernel_panic() {
        let dmesg = "kernel panic - not syncing: stack smashing detected\nCall Trace:\n test_func+0x10/0x20\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::StackOverflow);
    }

    #[test]
    fn test_assign_cwe_coverage() {
        let cases = vec![
            (CrashType::UseAfterFree, "CWE-416", Severity::Critical),
            (CrashType::OutOfBoundsRead, "CWE-125", Severity::High),
            (CrashType::OutOfBoundsWrite, "CWE-787", Severity::Critical),
            (CrashType::DoubleFree, "CWE-415", Severity::Critical),
            (CrashType::DataRace, "CWE-362", Severity::High),
            (CrashType::NullPointerDeref, "CWE-476", Severity::High),
            (CrashType::StackOverflow, "CWE-121", Severity::Critical),
            (CrashType::InfoLeak, "CWE-200", Severity::High),
            (CrashType::Rop, "CWE-269", Severity::Critical),
            (CrashType::UninitMemory, "CWE-457", Severity::Medium),
            (CrashType::KernelPanic, "CWE-20", Severity::High),
            (CrashType::Unknown, "CWE-119", Severity::Medium),
        ];

        for (crash_type, expected_cwe, expected_severity) in cases {
            let (cwe, severity) = assign_cwe(&crash_type);
            assert_eq!(cwe, expected_cwe, "CWE mismatch for {crash_type:?}");
            assert_eq!(
                severity, expected_severity,
                "Severity mismatch for {crash_type:?}"
            );
        }
    }

    #[test]
    fn test_crash_triage_deduplication() {
        let mut triage = CrashTriage::new();

        let sig1 = CrashSignature {
            hash: "abc123".to_string(),
            crash_type: CrashType::UseAfterFree,
            symptom: "use-after-free in func1".to_string(),
            backtrace_frames: vec!["frame1".to_string()],
        };
        let sig2 = CrashSignature {
            hash: "abc123".to_string(),
            crash_type: CrashType::UseAfterFree,
            symptom: "use-after-free in func1".to_string(),
            backtrace_frames: vec!["frame1".to_string()],
        };
        let sig3 = CrashSignature {
            hash: "def456".to_string(),
            crash_type: CrashType::DoubleFree,
            symptom: "double-free in func2".to_string(),
            backtrace_frames: vec!["frame2".to_string()],
        };

        triage.add_crash(CrashEntry {
            signature: sig1,
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        });
        triage.add_crash(CrashEntry {
            signature: sig2,
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        });
        triage.add_crash(CrashEntry {
            signature: sig3,
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        });

        let report = triage.triage();
        assert_eq!(report.total_crashes, 3);
        assert_eq!(report.unique_crashes, 2);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.cwe_counts.get("CWE-416"), Some(&1));
        assert_eq!(report.cwe_counts.get("CWE-415"), Some(&1));
    }

    #[test]
    fn test_syzkaller_config_generation() {
        let config = SyzkallerConfig::default();
        let cfg = SyzkallerRunner::generate_config(&config);
        assert!(cfg.contains("syzkaller"));
        assert!(cfg.contains("amd64"));
        assert!(cfg.contains("4096"));
    }

    #[test]
    fn test_minimize_input() {
        let input = b"AAABBBCCC";
        let result = minimize_input(input, |data| data.len() >= 3, 100);
        assert!(result.len() <= input.len());
        assert!(!result.is_empty());
    }

    #[test]
    fn test_minimize_input_no_crash() {
        let input = b"AAABBBCCC";
        let result = minimize_input(input, |_data| false, 100);
        assert_eq!(result, input);
    }

    // ================================================================
    // Additional CrashSignature tests
    // ================================================================

    #[test]
    fn test_crash_signature_oob_read() {
        let dmesg = r#"BUG: KASAN: out-of-bounds read in read_func+0x40/0x80
Read of size 2 at addr ffff8880aabbcc00 by task test/9999
Call Trace:
 read_func+0x40/0x80
"#;
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::OutOfBoundsRead);
        assert_eq!(sig.backtrace_frames.len(), 1);
        assert!(!sig.hash.is_empty());
    }

    #[test]
    fn test_crash_signature_double_free() {
        let dmesg = r#"BUG: KASAN: double-free or invalid-free in free_func+0x60/0x100
CPU: 0 PID: 1111
Call Trace:
 free_func+0x60/0x100
"#;
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::DoubleFree);
    }

    #[test]
    fn test_crash_signature_data_race() {
        let dmesg = "BUG: KCSAN: data-race in tcp_poll+0x100/0x200\nCall Trace:\n tcp_poll+0x100/0x200\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::DataRace);
    }

    #[test]
    fn test_crash_signature_uninit_memory() {
        let dmesg = "BUG: KMSAN: uninit-value in copy_to_user_func+0x10/0x20\nCall Trace:\n copy_to_user_func+0x10/0x20\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::UninitMemory);
    }

    #[test]
    fn test_crash_signature_kernel_panic_no_stack_smash() {
        let dmesg = "kernel panic - not syncing: VFS: Unable to mount root fs\nCall Trace:\n mount_root+0x10/0x20\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::KernelPanic);
    }

    #[test]
    fn test_crash_signature_general_protection_fault() {
        let dmesg = "general protection fault: 0000 [#1] SMP\nCall Trace:\n fault_func+0x10/0x20\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::NullPointerDeref);
    }

    #[test]
    fn test_crash_signature_page_fault() {
        let dmesg = "page fault in func+0x100/0x200\nCall Trace:\n func+0x100/0x200\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::NullPointerDeref);
    }

    #[test]
    fn test_crash_signature_rip_register() {
        let dmesg = "RIP: 0010:exploit_func+0x100/0x200\nCall Trace:\n exploit_func+0x100/0x200\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::Rop);
    }

    #[test]
    fn test_crash_signature_eip_register() {
        let dmesg = "EIP: 0010:exploit_func+0x100/0x200\nCall Trace:\n func+0x10/0x20\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::Rop);
    }

    #[test]
    fn test_crash_signature_pc_register() {
        let dmesg = "pc : func+0x100/0x200\nlr : caller+0x20/0x40\nCall Trace:\n func+0x100/0x200\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::Rop);
    }

    #[test]
    fn test_crash_signature_wild_memory_access() {
        let dmesg = r#"BUG: KASAN: wild-memory-access in wild_func+0x30/0x60
Read of size 8 at addr 0000000000000010 by task test/6666
Call Trace:
 wild_func+0x30/0x60
"#;
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::NullPointerDeref);
    }

    #[test]
    fn test_crash_signature_unknown() {
        let dmesg = "Some random unrelated output\nNo crash info here\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.crash_type, CrashType::Unknown);
    }

    #[test]
    fn test_crash_signature_empty_backtrace() {
        let dmesg = "BUG: KASAN: use-after-free in f+0x10/0x20\nRead of size 4 at addr ffff888000000001\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert!(sig.backtrace_frames.is_empty());
        assert_eq!(sig.hash.len(), 16);
    }

    #[test]
    fn test_crash_signature_backtrace_frames() {
        let dmesg = "BUG: KASAN: use-after-free in f+0x10/0x20\nCall Trace:\n frame1+0x10/0x20\nframe2+0x20/0x40\nframe3+0x30/0x60\n\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.backtrace_frames.len(), 3);
    }

    #[test]
    fn test_crash_signature_backtrace_terminates_on_empty_line() {
        let dmesg = "BUG: KASAN: use-after-free in f+0x10/0x20\nCall Trace:\n frame1+0x10/0x20\n\nframe2+0x20/0x40\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.backtrace_frames.len(), 1);
    }

    #[test]
    fn test_crash_signature_backtrace_terminates_on_dashes() {
        let dmesg = "BUG: KASAN: use-after-free in f+0x10/0x20\nCall Trace:\n frame1+0x10/0x20\n---[ end trace ]---\nframe2+0x20/0x40\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig.backtrace_frames.len(), 1);
    }

    #[test]
    fn test_crash_signature_symptom_extraction() {
        let dmesg = "BUG: KASAN: out-of-bounds write in my_driver+0x50/0x100\nWrite of size 8\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert!(sig.symptom.contains("KASAN"));
        assert!(sig.symptom.contains("out-of-bounds write"));
    }

    #[test]
    fn test_crash_signature_symptom_kernel_panic() {
        let dmesg = "kernel panic - not syncing: Oops\nCall Trace:\n func+0x10/0x20\n";
        let sig = CrashSignature::from_dmesg(dmesg).unwrap();
        assert!(sig.symptom.contains("kernel panic"));
    }

    #[test]
    fn test_crash_signature_hash_deterministic() {
        let dmesg = "BUG: KASAN: use-after-free in f+0x10/0x20\nCall Trace:\n frame1+0x10/0x20\n";
        let sig1 = CrashSignature::from_dmesg(dmesg).unwrap();
        let sig2 = CrashSignature::from_dmesg(dmesg).unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[test]
    fn test_crash_signature_different_traces_different_hashes() {
        let dmesg1 = "BUG: KASAN: use-after-free in f+0x10/0x20\nCall Trace:\n func_a+0x10/0x20\n";
        let dmesg2 = "BUG: KASAN: use-after-free in f+0x10/0x20\nCall Trace:\n func_b+0x10/0x20\n";
        let sig1 = CrashSignature::from_dmesg(dmesg1).unwrap();
        let sig2 = CrashSignature::from_dmesg(dmesg2).unwrap();
        assert_ne!(sig1.hash, sig2.hash);
    }

    // ================================================================
    // CrashTriage and deduplication
    // ================================================================

    #[test]
    fn test_triage_empty() {
        let triage = CrashTriage::new();
        let report = triage.triage();
        assert_eq!(report.total_crashes, 0);
        assert_eq!(report.unique_crashes, 0);
        assert!(report.findings.is_empty());
        assert!(report.cwe_counts.is_empty());
        assert!(report.crash_type_counts.is_empty());
    }

    #[test]
    fn test_triage_all_unique() {
        let mut triage = CrashTriage::new();
        for i in 0..5 {
            triage.add_crash(CrashEntry {
                signature: CrashSignature {
                    hash: format!("hash_{i}"),
                    crash_type: CrashType::UseAfterFree,
                    symptom: format!("uaf in func{i}"),
                    backtrace_frames: vec![format!("frame{i}")],
                },
                input_path: None,
                dmesg_log: String::new(),
                timestamp: chrono::Utc::now(),
                fuzzer: "test".to_string(),
            });
        }
        let report = triage.triage();
        assert_eq!(report.total_crashes, 5);
        assert_eq!(report.unique_crashes, 5);
        assert_eq!(report.findings.len(), 5);
    }

    #[test]
    fn test_triage_all_duplicates() {
        let mut triage = CrashTriage::new();
        for _ in 0..5 {
            triage.add_crash(CrashEntry {
                signature: CrashSignature {
                    hash: "same_hash".to_string(),
                    crash_type: CrashType::DoubleFree,
                    symptom: "double free in func".to_string(),
                    backtrace_frames: vec!["frame".to_string()],
                },
                input_path: None,
                dmesg_log: String::new(),
                timestamp: chrono::Utc::now(),
                fuzzer: "test".to_string(),
            });
        }
        let report = triage.triage();
        assert_eq!(report.total_crashes, 5);
        assert_eq!(report.unique_crashes, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.cwe_counts.get("CWE-415"), Some(&1));
    }

    #[test]
    fn test_deduplicate_preserves_first() {
        let mut triage = CrashTriage::new();
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "abc".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "first".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "t".to_string(),
        });
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "abc".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "second".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "t".to_string(),
        });
        let unique = triage.deduplicate();
        assert_eq!(unique.len(), 1);
        assert_eq!(unique[0].signature.symptom, "first");
    }

    #[test]
    fn test_triage_mixed_crash_types() {
        let mut triage = CrashTriage::new();
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "h1".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "uaf".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "t".to_string(),
        });
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "h2".to_string(),
                crash_type: CrashType::DataRace,
                symptom: "race".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "t".to_string(),
        });
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "h3".to_string(),
                crash_type: CrashType::OutOfBoundsWrite,
                symptom: "oob".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "t".to_string(),
        });
        let report = triage.triage();
        assert_eq!(report.unique_crashes, 3);
        assert_eq!(report.cwe_counts.len(), 3);
        assert!(report.cwe_counts.contains_key("CWE-416"));
        assert!(report.cwe_counts.contains_key("CWE-362"));
        assert!(report.cwe_counts.contains_key("CWE-787"));
    }

    #[test]
    fn test_triage_finding_severity_mapping() {
        let mut triage = CrashTriage::new();
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "h1".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "uaf".to_string(),
                backtrace_frames: vec!["frame1".to_string()],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        });
        let report = triage.triage();
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.cwe.as_deref(), Some("CWE-416"));
        assert!(f.description.contains("Fuzzing crash"));
        assert!(f.description.contains("1 occurrences"));
    }

    #[test]
    fn test_triage_finding_with_occurrence_count() {
        let mut triage = CrashTriage::new();
        for _ in 0..10 {
            triage.add_crash(CrashEntry {
                signature: CrashSignature {
                    hash: "same".to_string(),
                    crash_type: CrashType::NullPointerDeref,
                    symptom: "null deref".to_string(),
                    backtrace_frames: vec![],
                },
                input_path: None,
                dmesg_log: String::new(),
                timestamp: chrono::Utc::now(),
                fuzzer: "test".to_string(),
            });
        }
        let report = triage.triage();
        assert_eq!(report.unique_crashes, 1);
        assert!(report.findings[0].description.contains("10 occurrences"));
    }

    #[test]
    fn test_triage_finding_confidence() {
        let mut triage = CrashTriage::new();
        triage.add_crash(CrashEntry {
            signature: CrashSignature {
                hash: "h1".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "uaf".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        });
        let report = triage.triage();
        let f = &report.findings[0];
        assert_eq!(f.confidence, 0.85);
        assert_eq!(f.discovery_method, DiscoveryMethod::Fuzzing);
    }

    // ================================================================
    // assign_cwe tests
    // ================================================================

    #[test]
    fn test_assign_cwe_oob_read() {
        let (cwe, sev) = assign_cwe(&CrashType::OutOfBoundsRead);
        assert_eq!(cwe, "CWE-125");
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn test_assign_cwe_null_pointer() {
        let (cwe, sev) = assign_cwe(&CrashType::NullPointerDeref);
        assert_eq!(cwe, "CWE-476");
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn test_assign_cwe_info_leak() {
        let (cwe, sev) = assign_cwe(&CrashType::InfoLeak);
        assert_eq!(cwe, "CWE-200");
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn test_assign_cwe_kernel_panic() {
        let (cwe, sev) = assign_cwe(&CrashType::KernelPanic);
        assert_eq!(cwe, "CWE-20");
        assert_eq!(sev, Severity::High);
    }

    // ================================================================
    // minimize_input tests
    // ================================================================

    #[test]
    fn test_minimize_already_minimal() {
        let input = b"A";
        let result = minimize_input(input, |data| data.len() >= 1, 100);
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_minimize_to_empty_not_possible() {
        let input = b"ABCD";
        let result = minimize_input(input, |data| !data.is_empty(), 100);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_minimize_zero_iterations() {
        let input = b"AAAA";
        let result = minimize_input(input, |_data| true, 0);
        assert_eq!(result, input);
    }

    #[test]
    fn test_minimize_removable_bytes() {
        let input = b"AxBxCx";
        let result = minimize_input(input, |data| {
            data.windows(1).any(|w| w == b"x")
        }, 100);
        assert!(result.len() <= input.len());
        assert!(!result.is_empty());
    }

    #[test]
    fn test_minimize_non_reproducible_input() {
        let input = b"AAAA";
        let result = minimize_input(input, |_data| false, 100);
        assert_eq!(result, input);
    }

    // ================================================================
    // SyzkallerConfig tests
    // ================================================================

    #[test]
    fn test_syzkaller_config_default_values() {
        let config = SyzkallerConfig::default();
        assert_eq!(config.arch, "amd64");
        assert_eq!(config.cpus, 4);
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.timeout_secs, 3600);
        assert!(config.targets.is_empty());
    }

    #[test]
    fn test_syzkaller_config_generation_contains_all_fields() {
        let config = SyzkallerConfig {
            workdir: PathBuf::from("/tmp/test"),
            kernel_image: PathBuf::from("/boot/vmlinuz"),
            arch: "arm64".to_string(),
            cpus: 8,
            memory_mb: 8192,
            timeout_secs: 7200,
            targets: vec!["net".to_string()],
        };
        let cfg = SyzkallerRunner::generate_config(&config);
        assert!(cfg.contains("arm64"));
        assert!(cfg.contains("8192"));
        assert!(cfg.contains("/tmp/test"));
        assert!(cfg.contains("/boot/vmlinuz"));
        assert!(cfg.contains("8"));
    }

    #[test]
    fn test_syzkaller_config_generation_sandbox() {
        let config = SyzkallerConfig::default();
        let cfg = SyzkallerRunner::generate_config(&config);
        assert!(cfg.contains("sandbox/namespace"));
        assert!(cfg.contains("\"cover\": true"));
        assert!(cfg.contains("\"reproduce\": true"));
    }

    // ================================================================
    // KaflConfig tests
    // ================================================================

    #[test]
    fn test_kafl_config_default() {
        let config = KaflConfig::default();
        assert_eq!(config.workdir, PathBuf::from("/tmp/kraken-kaf"));
        assert_eq!(config.ram_size, 256);
        assert_eq!(config.timeout_secs, 3600);
        assert!(!config.persistent);
        assert!(config.shares_file.is_none());
    }

    #[test]
    fn test_kafl_config_custom() {
        let config = KaflConfig {
            workdir: PathBuf::from("/custom/workdir"),
            kernel_image: PathBuf::from("/boot/vmlinuz"),
            ram_size: 512,
            shares_file: Some(PathBuf::from("/shares.json")),
            timeout_secs: 1800,
            persistent: true,
        };
        assert_eq!(config.ram_size, 512);
        assert!(config.persistent);
        assert!(config.shares_file.is_some());
    }

    // ================================================================
    // Exploit generation tests
    // ================================================================

    #[test]
    fn test_generate_exploit_uaf() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "abc".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "use-after-free in kfree+0x100/0x200".to_string(),
                backtrace_frames: vec!["kfree+0x100/0x200".to_string()],
            },
            input_path: Some(PathBuf::from("/tmp/crash")),
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "syzkaller".to_string(),
        };
        let finding = generate_exploit_from_crash(&entry, Some("6.8.12"), "amd64").unwrap();
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.exploit_type, Some(ExploitType::PrivilegeEscalation));
        assert!(finding.exploit_code.is_some());
        assert!(finding.exploit_code.unwrap().contains("kfree+0x100/0x200"));
        assert!(finding.description.contains("Exploit PoC"));
        assert_eq!(finding.status, crate::FindingStatus::InTriage);
    }

    #[test]
    fn test_generate_exploit_oob_write() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "def".to_string(),
                crash_type: CrashType::OutOfBoundsWrite,
                symptom: "oob write in vuln_func".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "kafl".to_string(),
        };
        let finding = generate_exploit_from_crash(&entry, None, "arm64").unwrap();
        assert_eq!(finding.cwe.as_deref(), Some("CWE-787"));
        assert!(finding.exploit_code.unwrap().contains("arm64"));
    }

    #[test]
    fn test_generate_exploit_double_free() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "ghi".to_string(),
                crash_type: CrashType::DoubleFree,
                symptom: "double-free in func".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        let finding = generate_exploit_from_crash(&entry, Some("5.15.0"), "x86").unwrap();
        assert_eq!(finding.cwe.as_deref(), Some("CWE-415"));
        assert!(finding.exploit_code.is_some());
    }

    #[test]
    fn test_no_exploit_for_data_race() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "jkl".to_string(),
                crash_type: CrashType::DataRace,
                symptom: "data race".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        assert!(generate_exploit_from_crash(&entry, None, "amd64").is_none());
    }

    #[test]
    fn test_no_exploit_for_oob_read() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "mno".to_string(),
                crash_type: CrashType::OutOfBoundsRead,
                symptom: "oob read".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        assert!(generate_exploit_from_crash(&entry, None, "amd64").is_none());
    }

    #[test]
    fn test_no_exploit_for_null_deref() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "pqr".to_string(),
                crash_type: CrashType::NullPointerDeref,
                symptom: "null deref".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        assert!(generate_exploit_from_crash(&entry, None, "amd64").is_none());
    }

    #[test]
    fn test_no_exploit_for_stack_overflow() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "stu".to_string(),
                crash_type: CrashType::StackOverflow,
                symptom: "stack smashing".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        assert!(generate_exploit_from_crash(&entry, None, "amd64").is_none());
    }

    #[test]
    fn test_exploit_unknown_kernel_version() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "vwx".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "uaf".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        let finding = generate_exploit_from_crash(&entry, None, "amd64").unwrap();
        assert!(finding.exploit_code.unwrap().contains("unknown"));
    }

    #[test]
    fn test_exploit_generation_cvss() {
        let entry = CrashEntry {
            signature: CrashSignature {
                hash: "abc".to_string(),
                crash_type: CrashType::UseAfterFree,
                symptom: "uaf".to_string(),
                backtrace_frames: vec![],
            },
            input_path: None,
            dmesg_log: String::new(),
            timestamp: chrono::Utc::now(),
            fuzzer: "test".to_string(),
        };
        let finding = generate_exploit_from_crash(&entry, Some("6.8.0"), "amd64").unwrap();
        assert_eq!(finding.cvss_score, Some(9.5));
    }
}
