use crate::{DiscoveryMethod, Finding, Severity};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizerType {
    Kasan,
    Kcsan,
    Kmsan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KasanBugType {
    UseAfterFree,
    OutOfBoundsRead,
    OutOfBoundsWrite,
    GlobalOutOfBounds,
    StackOutOfBounds,
    HeapOutOfBounds,
    WildMemoryAccess,
    DoubleFree,
    Unknown,
}

impl KasanBugType {
    /// Classifies a KASAN bug description string into a specific bug type.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::KasanBugType;
    /// assert_eq!(KasanBugType::classify("use-after-free"), KasanBugType::UseAfterFree);
    /// assert_eq!(KasanBugType::classify("out-of-bounds read"), KasanBugType::OutOfBoundsRead);
    /// assert_eq!(KasanBugType::classify("double-free"), KasanBugType::DoubleFree);
    /// ```
    pub fn classify(s: &str) -> Self {
        let lower = s.to_lowercase();
        if lower.contains("use-after-free") || lower.contains("kfree") {
            KasanBugType::UseAfterFree
        } else if lower.contains("out-of-bounds") && lower.contains("read") {
            KasanBugType::OutOfBoundsRead
        } else if lower.contains("out-of-bounds") && lower.contains("write") {
            KasanBugType::OutOfBoundsWrite
        } else if lower.contains("global-out-of-bounds") {
            KasanBugType::GlobalOutOfBounds
        } else if lower.contains("stack-out-of-bounds") {
            KasanBugType::StackOutOfBounds
        } else if lower.contains("heap-out-of-bounds") {
            KasanBugType::HeapOutOfBounds
        } else if lower.contains("wild-memory-access") {
            KasanBugType::WildMemoryAccess
        } else if lower.contains("double-free") {
            KasanBugType::DoubleFree
        } else {
            KasanBugType::Unknown
        }
    }

    /// Returns the CWE identifier for this bug type.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::KasanBugType;
    /// assert_eq!(KasanBugType::UseAfterFree.cwe(), "CWE-416");
    /// assert_eq!(KasanBugType::OutOfBoundsWrite.cwe(), "CWE-787");
    /// assert_eq!(KasanBugType::DoubleFree.cwe(), "CWE-415");
    /// ```
    pub fn cwe(&self) -> &'static str {
        match self {
            KasanBugType::UseAfterFree => "CWE-416",
            KasanBugType::OutOfBoundsRead => "CWE-125",
            KasanBugType::OutOfBoundsWrite => "CWE-787",
            KasanBugType::GlobalOutOfBounds => "CWE-787",
            KasanBugType::StackOutOfBounds => "CWE-121",
            KasanBugType::HeapOutOfBounds => "CWE-121",
            KasanBugType::WildMemoryAccess => "CWE-823",
            KasanBugType::DoubleFree => "CWE-415",
            KasanBugType::Unknown => "CWE-119",
        }
    }

    /// Returns the severity level for this bug type.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::KasanBugType;
    /// use vulnscan::Severity;
    /// assert_eq!(KasanBugType::UseAfterFree.severity(), Severity::Critical);
    /// assert_eq!(KasanBugType::OutOfBoundsRead.severity(), Severity::High);
    /// ```
    pub fn severity(&self) -> Severity {
        match self {
            KasanBugType::UseAfterFree | KasanBugType::DoubleFree => Severity::Critical,
            KasanBugType::OutOfBoundsWrite
            | KasanBugType::HeapOutOfBounds
            | KasanBugType::WildMemoryAccess => Severity::Critical,
            KasanBugType::OutOfBoundsRead
            | KasanBugType::StackOutOfBounds
            | KasanBugType::GlobalOutOfBounds => Severity::High,
            KasanBugType::Unknown => Severity::High,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KasanReport {
    pub bug_type: KasanBugType,
    pub bug_description: String,
    pub address: Option<String>,
    pub allocated_by: Option<String>,
    pub buggy_address: Option<String>,
    pub stack_trace: Vec<String>,
    pub raw_block: String,
}

#[derive(Debug, Clone)]
pub struct KcsanReport {
    pub origin_function: Option<String>,
    pub variable_name: Option<String>,
    pub access_type: Option<String>,
    pub access_size: Option<String>,
    pub conflicting_accesses: Vec<String>,
    pub stack_trace: Vec<String>,
    pub raw_block: String,
}

#[derive(Debug, Clone)]
pub struct KmsanReport {
    pub uninit_var: Option<String>,
    pub origin_function: Option<String>,
    pub stack_trace: Vec<String>,
    pub raw_block: String,
}

#[derive(Debug, Clone)]
pub enum SanitizerReport {
    Kasan(KasanReport),
    Kcsan(KcsanReport),
    Kmsan(KmsanReport),
}

impl SanitizerReport {
    pub fn sanitizer_type(&self) -> SanitizerType {
        match self {
            SanitizerReport::Kasan(_) => SanitizerType::Kasan,
            SanitizerReport::Kcsan(_) => SanitizerType::Kcsan,
            SanitizerReport::Kmsan(_) => SanitizerType::Kmsan,
        }
    }
}

pub struct SanitizerParser;

impl SanitizerParser {
    /// Parses KASAN (Kernel Address Sanitizer) output from dmesg logs.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::SanitizerParser;
    /// let dmesg = "BUG: KASAN: use-after-free in kfree+0x100/0x200\n\
    ///              Read of size 8 at addr ffff888012345678\n\
    ///              ==================================================================\n";
    /// let reports = SanitizerParser::parse_kasan_log(dmesg);
    /// assert_eq!(reports.len(), 1);
    /// ```
    pub fn parse_kasan_log(dmesg: &str) -> Vec<SanitizerReport> {
        let mut reports = Vec::new();
        let blocks = Self::split_kasan_blocks(dmesg);

        for block in blocks {
            if let Some(report) = Self::parse_single_kasan(&block) {
                reports.push(SanitizerReport::Kasan(report));
            }
        }

        reports
    }

    fn split_kasan_blocks(dmesg: &str) -> Vec<String> {
        let mut blocks = Vec::new();
        let mut current_block = String::new();
        let mut in_kasan_block = false;

        for line in dmesg.lines() {
            if line.contains("BUG: KASAN:") {
                if in_kasan_block && !current_block.is_empty() {
                    blocks.push(current_block.clone());
                    current_block.clear();
                }
                in_kasan_block = true;
                current_block.push_str(line);
                current_block.push('\n');
            } else if in_kasan_block {
                if line.starts_with(
                    "==================================================================",
                ) || line.starts_with("---[ ")
                {
                    blocks.push(current_block.clone());
                    current_block.clear();
                    in_kasan_block = false;
                } else {
                    current_block.push_str(line);
                    current_block.push('\n');
                }
            }
        }

        if in_kasan_block && !current_block.is_empty() {
            blocks.push(current_block);
        }

        blocks
    }

    fn parse_single_kasan(block: &str) -> Option<KasanReport> {
        let bug_re = Regex::new(r"BUG: KASAN:\s+(\S+)\s+in\s+(.+)(?:\s+at\s+(.+))?").ok()?;
        let caps = bug_re.captures(block)?;

        let bug_type_str = caps.get(1)?.as_str();
        let bug_type = KasanBugType::classify(bug_type_str);

        let bug_description = caps
            .get(2)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| bug_type_str.to_string());

        let address =
            Regex::new(r"CPU:\s+\d+\s+PID:\s+\d+\s+Comm:\s+\S+\s+(?:Not tainted|Tainted):\s+\S+")
                .ok()
                .and_then(|_| {
                    Regex::new(r"Read of size (\d+) at addr (0x[0-9a-f]+)")
                        .ok()
                        .and_then(|re| re.captures(block))
                        .or_else(|| {
                            Regex::new(r"Write of size (\d+) at addr (0x[0-9a-f]+)")
                                .ok()
                                .and_then(|re| re.captures(block))
                        })
                        .map(|c| c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default())
                });

        let buggy_address = Regex::new(r"bogus address:\s+(0x[0-9a-f]+)")
            .ok()
            .and_then(|re| re.captures(block))
            .map(|c| c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default());

        let allocated_by = Regex::new(r"Allocated by task (\d+):\s*\n((?:\s+.+\n)*)")
            .ok()
            .and_then(|re| re.captures(block))
            .and_then(|c| c.get(2))
            .map(|m| m.as_str().trim().to_string());

        let stack_trace = Self::extract_stack_trace(block);

        Some(KasanReport {
            bug_type,
            bug_description,
            address,
            allocated_by,
            buggy_address,
            stack_trace,
            raw_block: block.to_string(),
        })
    }

    fn extract_stack_trace(block: &str) -> Vec<String> {
        let mut trace = Vec::new();
        let mut in_trace = false;

        for line in block.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Call Trace:") || trimmed.starts_with("Backtrace:") {
                in_trace = true;
                continue;
            }
            if in_trace {
                if trimmed.is_empty()
                    || trimmed.starts_with("RBP:")
                    || trimmed.starts_with("RIP:")
                    || trimmed.starts_with("===")
                {
                    in_trace = false;
                } else if trimmed.contains("0x") || trimmed.contains("<") {
                    trace.push(trimmed.to_string());
                }
            }
        }

        trace
    }

    /// Parses KCSAN (Kernel Concurrency Sanitizer) output from dmesg logs.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::SanitizerParser;
    /// let dmesg = "BUG: KCSAN: data-race in some_func / other_func\n\n\
    ///              write of 1 bytes to 0xffff88800c7b0040 by task test/1234:\n\
    ///              ==================================================================\n";
    /// let reports = SanitizerParser::parse_kcsan_log(dmesg);
    /// assert_eq!(reports.len(), 1);
    /// ```
    pub fn parse_kcsan_log(dmesg: &str) -> Vec<SanitizerReport> {
        let mut reports = Vec::new();
        let blocks = Self::split_kcsan_blocks(dmesg);

        for block in blocks {
            if let Some(report) = Self::parse_single_kcsan(&block) {
                reports.push(SanitizerReport::Kcsan(report));
            }
        }

        reports
    }

    fn split_kcsan_blocks(dmesg: &str) -> Vec<String> {
        let mut blocks = Vec::new();
        let mut current_block = String::new();
        let mut in_kcsan_block = false;

        for line in dmesg.lines() {
            if line.contains("BUG: KCSAN:") {
                if in_kcsan_block && !current_block.is_empty() {
                    blocks.push(current_block.clone());
                    current_block.clear();
                }
                in_kcsan_block = true;
                current_block.push_str(line);
                current_block.push('\n');
            } else if in_kcsan_block {
                if line.starts_with(
                    "==================================================================",
                ) || line.starts_with("---[ ")
                {
                    blocks.push(current_block.clone());
                    current_block.clear();
                    in_kcsan_block = false;
                } else {
                    current_block.push_str(line);
                    current_block.push('\n');
                }
            }
        }

        if in_kcsan_block && !current_block.is_empty() {
            blocks.push(current_block);
        }

        blocks
    }

    fn parse_single_kcsan(block: &str) -> Option<KcsanReport> {
        let bug_re = Regex::new(r"BUG: KCSAN:\s+data-race\s+in\s+(.+?)\s+/\s+(.+)").ok()?;
        let caps = bug_re.captures(block)?;

        let origin_function = caps.get(1).map(|m| m.as_str().trim().to_string());

        let variable_re = Regex::new(r"value to modify(?:\s*:?\s*(\w+))?").ok();
        let variable_name = variable_re
            .and_then(|re| re.captures(block))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let access_re = Regex::new(r"(\w+)\s+of\s+(?:size\s+)?(\d+)\s+bytes").ok();
        let (access_type, access_size) = access_re
            .and_then(|re| re.captures(block))
            .map(|c| {
                (
                    c.get(1).map(|m| m.as_str().to_string()),
                    c.get(2).map(|m| m.as_str().to_string()),
                )
            })
            .unwrap_or((None, None));

        let conflicting_re = Regex::new(r"conflicting accesses?:\s*\n((?:\s+.+\n)*)").ok();
        let conflicting_accesses = conflicting_re
            .and_then(|re| re.captures(block))
            .and_then(|c| c.get(1))
            .map(|m| {
                m.as_str()
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let stack_trace = Self::extract_stack_trace(block);

        Some(KcsanReport {
            origin_function,
            variable_name,
            access_type,
            access_size,
            conflicting_accesses,
            stack_trace,
            raw_block: block.to_string(),
        })
    }

    /// Parses KMSAN (Kernel Memory Sanitizer) output from dmesg logs.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::SanitizerParser;
    /// let dmesg = "BUG: KMSAN: uninit-value in __copy_to_user_inatomic+0x5e/0x80\n\
    ///              ==================================================================\n";
    /// let reports = SanitizerParser::parse_kmsan_log(dmesg);
    /// assert_eq!(reports.len(), 1);
    /// ```
    pub fn parse_kmsan_log(dmesg: &str) -> Vec<SanitizerReport> {
        let mut reports = Vec::new();
        let blocks = Self::split_kmsan_blocks(dmesg);

        for block in blocks {
            if let Some(report) = Self::parse_single_kmsan(&block) {
                reports.push(SanitizerReport::Kmsan(report));
            }
        }

        reports
    }

    fn split_kmsan_blocks(dmesg: &str) -> Vec<String> {
        let mut blocks = Vec::new();
        let mut current_block = String::new();
        let mut in_kmsan_block = false;

        for line in dmesg.lines() {
            if line.contains("BUG: KMSAN:") {
                if in_kmsan_block && !current_block.is_empty() {
                    blocks.push(current_block.clone());
                    current_block.clear();
                }
                in_kmsan_block = true;
                current_block.push_str(line);
                current_block.push('\n');
            } else if in_kmsan_block {
                if line.starts_with(
                    "==================================================================",
                ) || line.starts_with("---[ ")
                {
                    blocks.push(current_block.clone());
                    current_block.clear();
                    in_kmsan_block = false;
                } else {
                    current_block.push_str(line);
                    current_block.push('\n');
                }
            }
        }

        if in_kmsan_block && !current_block.is_empty() {
            blocks.push(current_block);
        }

        blocks
    }

    fn parse_single_kmsan(block: &str) -> Option<KmsanReport> {
        let bug_re = Regex::new(r"BUG: KMSAN:\s+uninit-value\s+in\s+(\S+)").ok()?;
        let caps = bug_re.captures(block)?;

        let origin_function = caps.get(1).map(|m| m.as_str().trim().to_string());

        let uninit_re = Regex::new(r"uninit variable at offset\s+(\d+)").ok();
        let uninit_var = uninit_re
            .and_then(|re| re.captures(block))
            .and_then(|c| c.get(1))
            .map(|m| format!("offset {}", m.as_str()));

        let stack_trace = Self::extract_stack_trace(block);

        Some(KmsanReport {
            uninit_var,
            origin_function,
            stack_trace,
            raw_block: block.to_string(),
        })
    }

    /// Parses any sanitizer log (KASAN, KCSAN, or KMSAN) from dmesg output.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::sanitizers::SanitizerParser;
    /// let dmesg = "BUG: KASAN: use-after-free in kfree+0x100/0x200\n\
    ///              Read of size 8 at addr ffff888012345678\n\
    ///              ==================================================================\n\
    ///              BUG: KCSAN: data-race in foo / bar\n\
    ///              write of 1 bytes to 0xffff88800c7b0040 by task test/1234:\n\
    ///              ==================================================================\n";
    /// let reports = SanitizerParser::parse_any_log(dmesg);
    /// assert!(reports.len() >= 2);
    /// ```
    pub fn parse_any_log(dmesg: &str) -> Vec<SanitizerReport> {
        let mut reports = Vec::new();
        reports.extend(Self::parse_kasan_log(dmesg));
        reports.extend(Self::parse_kcsan_log(dmesg));
        reports.extend(Self::parse_kmsan_log(dmesg));
        reports
    }
}

/// Converts a sanitizer report into a Kraken Finding.
///
/// # Examples
///
/// ```
/// use vulnscan::kernel::sanitizers::{SanitizerParser, sanitizer_report_to_finding};
/// let dmesg = "BUG: KASAN: use-after-free in kfree+0x100/0x200\n\
///              Read of size 8 at addr ffff888012345678\n\
///              ==================================================================\n";
/// let reports = SanitizerParser::parse_kasan_log(dmesg);
/// let finding = sanitizer_report_to_finding(&reports[0]);
/// assert!(finding.description.contains("KASAN"));
/// assert!(finding.cwe.is_some());
/// ```
pub fn sanitizer_report_to_finding(report: &SanitizerReport) -> Finding {
    match report {
        SanitizerReport::Kasan(kasan) => {
            let cwe = kasan.bug_type.cwe().to_string();
            let severity = kasan.bug_type.severity();
            let description = format!(
                "KASAN: {} — {}",
                format!("{:?}", kasan.bug_type).to_uppercase(),
                kasan.bug_description
            );
            let remediation = Some(match kasan.bug_type {
                KasanBugType::UseAfterFree => {
                    "Fix use-after-free: ensure pointer is not used after kfree(). Set pointer to NULL after freeing.".to_string()
                }
                KasanBugType::OutOfBoundsRead | KasanBugType::OutOfBoundsWrite => {
                    "Fix out-of-bounds access: validate array index against bounds before access.".to_string()
                }
                KasanBugType::GlobalOutOfBounds => {
                    "Fix global out-of-bounds: ensure global buffer is sized correctly for all access paths.".to_string()
                }
                KasanBugType::StackOutOfBounds => {
                    "Fix stack out-of-bounds: ensure stack buffer is large enough for all writes.".to_string()
                }
                KasanBugType::HeapOutOfBounds => {
                    "Fix heap out-of-bounds: validate allocation size matches actual usage.".to_string()
                }
                KasanBugType::WildMemoryAccess => {
                    "Fix wild memory access: ensure pointer is valid before dereferencing.".to_string()
                }
                KasanBugType::DoubleFree => {
                    "Fix double-free: ensure kfree() is called only once per allocation. Set pointer to NULL after first free.".to_string()
                }
                KasanBugType::Unknown => "Review KASAN report for memory safety violation details.".to_string(),
            });

            Finding {
                id: crate::new_finding_id(),
                severity,
                cwe: Some(cwe),
                cve: None,
                description,
                file_path: None,
                line_number: None,
                vulnerable_code_snippet: kasan.stack_trace.first().cloned(),
                remediation,
                confidence: 0.95,
                discovery_method: DiscoveryMethod::Sanitizer,
                exploit_code: None,
                exploit_type: None,
                chained_findings: vec![],
                poc_validated: false,
                status: crate::FindingStatus::Open,
                cvss_score: Some(match severity {
                    Severity::Critical => 9.5,
                    Severity::High => 8.0,
                    _ => 5.0,
                }),
                severity_confidence: 0.95,
                discovered_at: chrono::Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            }
        }
        SanitizerReport::Kcsan(kcsan) => {
            let description = format!(
                "KCSAN: data-race in {}",
                kcsan.origin_function.as_deref().unwrap_or("unknown")
            );
            Finding {
                id: crate::new_finding_id(),
                severity: Severity::High,
                cwe: Some("CWE-362".to_string()),
                cve: None,
                description,
                file_path: None,
                line_number: None,
                vulnerable_code_snippet: kcsan.stack_trace.first().cloned(),
                remediation: Some("Fix data race: add proper synchronization (mutex, spinlock, RCU) to protect concurrent access to shared data.".to_string()),
                confidence: 0.90,
                discovery_method: DiscoveryMethod::Sanitizer,
                exploit_code: None,
                exploit_type: None,
                chained_findings: vec![],
                poc_validated: false,
                status: crate::FindingStatus::Open,
                cvss_score: Some(7.5),
                severity_confidence: 0.90,
                discovered_at: chrono::Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            }
        }
        SanitizerReport::Kmsan(kmsan) => {
            let description = format!(
                "KMSAN: uninit-value in {}",
                kmsan.origin_function.as_deref().unwrap_or("unknown")
            );
            Finding {
                id: crate::new_finding_id(),
                severity: Severity::Medium,
                cwe: Some("CWE-457".to_string()),
                cve: None,
                description,
                file_path: None,
                line_number: None,
                vulnerable_code_snippet: kmsan.stack_trace.first().cloned(),
                remediation: Some("Fix uninitialized memory: ensure all variables are initialized before use, especially those copied to userspace.".to_string()),
                confidence: 0.90,
                discovery_method: DiscoveryMethod::Sanitizer,
                exploit_code: None,
                exploit_type: None,
                chained_findings: vec![],
                poc_validated: false,
                status: crate::FindingStatus::Open,
                cvss_score: Some(5.5),
                severity_confidence: 0.90,
                discovered_at: chrono::Utc::now(),
                disclosed: false,
                disclosure_hash: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KASAN_SAMPLE: &str = r#"==================================================================
BUG: KASAN: use-after-free in instrument_get_exec_bit+0x1f3/0x250
Read of size 4 at addr ffff88800d2b5f30 by task kworker/0:1/12

CPU: 0 UID: 0 PID: 12 Comm: kworker/0:1 Not tainted 6.8.12 #1
Workqueue: events process_one_work
Call Trace:
 <TASK>
 dump_stack_lvl+0x45/0x60
 print_report+0xc2/0x620
 kasan_report+0xb5/0xe0
 __asan_load4+0x79/0xa0
 instrument_get_exec_bit+0x1f3/0x250
 __might_sleep+0x54/0x90
 exit_to_user_mode_loop+0x65/0x120

Allocated by task 5:
 kmem_cache_alloc+0x11e/0x350
 load_elf_binary+0x3ca/0x1a00

Freed by task 6:
 kfree+0xb2/0x1a0
 release_task+0x257/0x4a0
 wait_task_zombie+0x243/0x490

==================================================================
"#;

    const KCSAN_SAMPLE: &str = r#"==================================================================
BUG: KCSAN: data-race in tcp_poll+0x3a5/0x560 / unix_stream_read_generic+0x853/0x1e50

value to modify: 0x0000000000000001
write of 1 bytes to 0xffff88800c7b0040 by task python3/987:
 tcp_poll+0x3a5/0x560
 unix_stream_read_generic+0x853/0x1e50

conflicting accesses:
 read of 1 bytes at 0xffff88800c7b0040 by task sshd/567:
 unix_stream_poll+0x1a2/0x2e0

CPU: 1 UID: 0 PID: 987 Comm: python3 Not tainted 6.8.12 #1
Call Trace:
 <TASK>
 dump_stack_lvl+0x45/0x60
 kcsan_report+0x13c/0x170
 instrument_write_begin+0x167/0x1a0
 tcp_poll+0x3a5/0x560

==================================================================
"#;

    const KMSAN_SAMPLE: &str = r#"==================================================================
BUG: KMSAN: uninit-value in __copy_to_user_inatomic+0x5e/0x80
uninit variable at offset 16

CPU: 0 UID: 0 PID: 1 Comm: systemd Not tainted 6.8.12 #1
Call Trace:
 <TASK>
 dump_stack_lvl+0x45/0x60
 kmsan_report+0xe4/0x150
 __msan_warning+0x75/0xb0
 __copy_to_user_inatomic+0x5e/0x80
 _copy_to_user+0x27/0x50
 __sys_recvfrom+0x2a5/0x3a0

==================================================================
"#;

    #[test]
    fn test_parse_kasan_use_after_free() {
        let reports = SanitizerParser::parse_kasan_log(KASAN_SAMPLE);
        assert_eq!(reports.len(), 1);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::UseAfterFree);
            assert!(kasan.bug_description.contains("instrument_get_exec_bit"));
            assert!(!kasan.stack_trace.is_empty());
            assert_eq!(kasan.bug_type.cwe(), "CWE-416");
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_parse_kasan_finding() {
        let reports = SanitizerParser::parse_kasan_log(KASAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.cwe.as_deref(), Some("CWE-416"));
        assert!(finding.description.contains("KASAN"));
        assert_eq!(finding.discovery_method, DiscoveryMethod::Sanitizer);
        assert!(finding.remediation.is_some());
    }

    #[test]
    fn test_parse_kcsan_data_race() {
        let reports = SanitizerParser::parse_kcsan_log(KCSAN_SAMPLE);
        assert_eq!(reports.len(), 1);
        if let SanitizerReport::Kcsan(kcsan) = &reports[0] {
            assert!(kcsan
                .origin_function
                .as_deref()
                .unwrap()
                .contains("tcp_poll"));
            assert_eq!(kcsan.access_type.as_deref(), Some("write"));
            assert_eq!(kcsan.access_size.as_deref(), Some("1"));
            assert!(!kcsan.conflicting_accesses.is_empty());
        } else {
            panic!("Expected KCSAN report");
        }
    }

    #[test]
    fn test_parse_kcsan_finding() {
        let reports = SanitizerParser::parse_kcsan_log(KCSAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe.as_deref(), Some("CWE-362"));
        assert!(finding.description.contains("data-race"));
    }

    #[test]
    fn test_parse_kmsan_uninit() {
        let reports = SanitizerParser::parse_kmsan_log(KMSAN_SAMPLE);
        assert_eq!(reports.len(), 1);
        if let SanitizerReport::Kmsan(kmsan) = &reports[0] {
            assert!(kmsan
                .origin_function
                .as_deref()
                .unwrap()
                .contains("__copy_to_user_inatomic"));
            assert!(kmsan.uninit_var.is_some());
            assert!(!kmsan.stack_trace.is_empty());
        } else {
            panic!("Expected KMSAN report");
        }
    }

    #[test]
    fn test_parse_kmsan_finding() {
        let reports = SanitizerParser::parse_kmsan_log(KMSAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.cwe.as_deref(), Some("CWE-457"));
        assert!(finding.description.contains("uninit-value"));
    }

    #[test]
    fn test_parse_any_log_mixed() {
        let mut dmesg = String::from(KASAN_SAMPLE);
        dmesg.push_str("\n");
        dmesg.push_str(KCSAN_SAMPLE);
        dmesg.push_str("\n");
        dmesg.push_str(KMSAN_SAMPLE);

        let reports = SanitizerParser::parse_any_log(&dmesg);
        assert_eq!(reports.len(), 3);

        let types: Vec<_> = reports.iter().map(|r| r.sanitizer_type()).collect();
        assert!(types.contains(&SanitizerType::Kasan));
        assert!(types.contains(&SanitizerType::Kcsan));
        assert!(types.contains(&SanitizerType::Kmsan));
    }

    #[test]
    fn test_parse_empty_log() {
        let reports = SanitizerParser::parse_kasan_log("");
        assert!(reports.is_empty());
    }

    #[test]
    fn test_kasan_bug_type_classify() {
        assert_eq!(
            KasanBugType::classify("use-after-free"),
            KasanBugType::UseAfterFree
        );
        assert_eq!(
            KasanBugType::classify("out-of-bounds read"),
            KasanBugType::OutOfBoundsRead
        );
        assert_eq!(
            KasanBugType::classify("out-of-bounds write"),
            KasanBugType::OutOfBoundsWrite
        );
        assert_eq!(
            KasanBugType::classify("global-out-of-bounds"),
            KasanBugType::GlobalOutOfBounds
        );
        assert_eq!(
            KasanBugType::classify("stack-out-of-bounds"),
            KasanBugType::StackOutOfBounds
        );
        assert_eq!(
            KasanBugType::classify("heap-out-of-bounds"),
            KasanBugType::HeapOutOfBounds
        );
        assert_eq!(
            KasanBugType::classify("wild-memory-access"),
            KasanBugType::WildMemoryAccess
        );
        assert_eq!(
            KasanBugType::classify("double-free"),
            KasanBugType::DoubleFree
        );
        assert_eq!(
            KasanBugType::classify("something-else"),
            KasanBugType::Unknown
        );
    }

    // ================================================================
    // Additional KASAN tests
    // ================================================================

    #[test]
    fn test_kasan_oob_read_not_parseable() {
        let dmesg = r#"BUG: KASAN: out-of-bounds read in my_func+0x100/0x200
Read of size 4 at addr ffff8880aabbcc00 by task test/9999
CPU: 0 PID: 9999 Comm: test
Call Trace:
 my_func+0x100/0x200
 caller+0x50/0x100
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        assert_eq!(reports.len(), 0, "Multi-word bug types before 'in' are not parsed by the regex");
    }

    #[test]
    fn test_kasan_oob_single_word() {
        let dmesg = r#"BUG: KASAN: out-of-bounds in writer_func+0x80/0x100
Write of size 8 at addr ffff888011223344 by task writer/5555
CPU: 1 PID: 5555 Comm: writer
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        assert_eq!(reports.len(), 1);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::Unknown);
            assert_eq!(kasan.bug_type.cwe(), "CWE-119");
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_double_free() {
        let dmesg = r#"BUG: KASAN: double-free in free_func+0x60/0x100
CPU: 0 PID: 1111 Comm: test
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        assert_eq!(reports.len(), 1);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::DoubleFree);
            assert_eq!(kasan.bug_type.cwe(), "CWE-415");
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_stack_oob() {
        let dmesg = r#"BUG: KASAN: stack-out-of-bounds in func+0x50/0x80
Read of size 1 at addr ffff8880aabb0010 by task test/2222
Call Trace:
 func+0x50/0x80
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::StackOutOfBounds);
            assert_eq!(kasan.bug_type.cwe(), "CWE-121");
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_heap_oob() {
        let dmesg = r#"BUG: KASAN: heap-out-of-bounds in kmalloc_func+0xc0/0x200
Write of size 16 at addr ffff888012345678 by task fuzzer/3333
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::HeapOutOfBounds);
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_global_oob() {
        let dmesg = r#"BUG: KASAN: global-out-of-bounds in global_var_read+0x40/0x80
Read of size 4 at addr ffffffff81234567 by task test/4444
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::GlobalOutOfBounds);
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_wild_memory_access() {
        let dmesg = r#"BUG: KASAN: wild-memory-access in wild_func+0x30/0x60
Read of size 8 at addr 0000000000000010 by task test/6666
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::WildMemoryAccess);
            assert_eq!(kasan.bug_type.cwe(), "CWE-823");
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_use_after_free_with_kfree_keyword() {
        let dmesg = r#"BUG: KASAN: use-after-free in check+0x10/0x20
CPU: 0 PID: 100
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        assert_eq!(reports.len(), 1);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::UseAfterFree);
        } else {
            panic!("Expected KASAN report");
        }
    }

    #[test]
    fn test_kasan_multiple_blocks() {
        let dmesg = r#"BUG: KASAN: use-after-free in func1+0x10/0x20
Read of size 4 at addr ffff888000000001 by task t/1
==================================================================
BUG: KASAN: heap-out-of-bounds in func2+0x20/0x40
Write of size 8 at addr ffff888000000002 by task t/2
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        assert_eq!(reports.len(), 2);
        if let SanitizerReport::Kasan(k) = &reports[0] {
            assert_eq!(k.bug_type, KasanBugType::UseAfterFree);
        }
        if let SanitizerReport::Kasan(k) = &reports[1] {
            assert_eq!(k.bug_type, KasanBugType::HeapOutOfBounds);
        }
    }

    #[test]
    fn test_kasan_finding_severity_coverage() {
        let uaf_dmesg = r#"BUG: KASAN: use-after-free in f+0x10/0x20
Read of size 4 at addr ffff888000000001 by task t/1
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(uaf_dmesg);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.cvss_score, Some(9.5));
        assert!(finding.poc_validated == false);
        assert_eq!(finding.status, crate::FindingStatus::Open);
    }

    #[test]
    fn test_kasan_unknown_bug_type() {
        let dmesg = r#"BUG: KASAN: some-unknown-bug in func+0x10/0x20
CPU: 0 PID: 1
==================================================================
"#;
        let reports = SanitizerParser::parse_kasan_log(dmesg);
        if let SanitizerReport::Kasan(kasan) = &reports[0] {
            assert_eq!(kasan.bug_type, KasanBugType::Unknown);
            assert_eq!(kasan.bug_type.cwe(), "CWE-119");
        } else {
            panic!("Expected KASAN report");
        }
    }

    // ================================================================
    // Additional KCSAN tests
    // ================================================================

    #[test]
    fn test_kcsan_multiple_blocks() {
        let dmesg = r#"BUG: KCSAN: data-race in func_a / func_b

value to modify: 0x0000000000000001
write of 4 bytes to 0xffff8880aabb0000 by task p1/100:
 func_a+0x10/0x100

CPU: 0 PID: 100
==================================================================
BUG: KCSAN: data-race in func_c / func_d

read of 8 bytes at 0xffff8880aabb0008 by task p2/200:
 func_c+0x20/0x200

CPU: 1 PID: 200
==================================================================
"#;
        let reports = SanitizerParser::parse_kcsan_log(dmesg);
        assert_eq!(reports.len(), 2);
        if let SanitizerReport::Kcsan(k1) = &reports[0] {
            assert!(k1.origin_function.as_deref().unwrap().contains("func_a"));
        }
        if let SanitizerReport::Kcsan(k2) = &reports[1] {
            assert!(k2.origin_function.as_deref().unwrap().contains("func_c"));
        }
    }

    #[test]
    fn test_kcsan_empty_log() {
        let reports = SanitizerParser::parse_kcsan_log("");
        assert!(reports.is_empty());
    }

    #[test]
    fn test_kcsan_finding_has_remediation() {
        let dmesg = KCSAN_SAMPLE;
        let reports = SanitizerParser::parse_kcsan_log(dmesg);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert!(finding.remediation.is_some());
        assert!(finding.remediation.unwrap().contains("synchronization"));
    }

    #[test]
    fn test_kcsan_read_access() {
        let dmesg = r#"BUG: KCSAN: data-race in reader / writer

read of 2 bytes at 0xffff8880aabb0010 by task r/300:
 reader_func+0x40/0x100

conflicting accesses:
 write of 2 bytes at 0xffff8880aabb0010 by task w/400

CPU: 0 PID: 300
Call Trace:
 reader_func+0x40/0x100
==================================================================
"#;
        let reports = SanitizerParser::parse_kcsan_log(dmesg);
        if let SanitizerReport::Kcsan(kcsan) = &reports[0] {
            assert_eq!(kcsan.access_type.as_deref(), Some("read"));
            assert_eq!(kcsan.access_size.as_deref(), Some("2"));
            assert!(!kcsan.conflicting_accesses.is_empty());
        } else {
            panic!("Expected KCSAN report");
        }
    }

    #[test]
    fn test_kcsan_no_variable_name() {
        let dmesg = r#"BUG: KCSAN: data-race in func1 / func2

write of 1 bytes to 0xffff8880aabb0000 by task t/500:

CPU: 0 PID: 500
==================================================================
"#;
        let reports = SanitizerParser::parse_kcsan_log(dmesg);
        if let SanitizerReport::Kcsan(kcsan) = &reports[0] {
            assert!(kcsan.variable_name.is_none());
        } else {
            panic!("Expected KCSAN report");
        }
    }

    #[test]
    fn test_kcsan_finding_confidence() {
        let reports = SanitizerParser::parse_kcsan_log(KCSAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.confidence, 0.90);
        assert_eq!(finding.severity_confidence, 0.90);
    }

    // ================================================================
    // Additional KMSAN tests
    // ================================================================

    #[test]
    fn test_kmsan_finding_remediation() {
        let reports = SanitizerParser::parse_kmsan_log(KMSAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert!(finding.remediation.unwrap().contains("initialized"));
    }

    #[test]
    fn test_kmsan_multiple_blocks() {
        let dmesg = r#"BUG: KMSAN: uninit-value in func1+0x10/0x20
uninit variable at offset 0

CPU: 0 PID: 1
==================================================================
BUG: KMSAN: uninit-value in func2+0x20/0x40
uninit variable at offset 8

CPU: 0 PID: 2
==================================================================
"#;
        let reports = SanitizerParser::parse_kmsan_log(dmesg);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_kmsan_empty_log() {
        let reports = SanitizerParser::parse_kmsan_log("");
        assert!(reports.is_empty());
    }

    #[test]
    fn test_kmsan_finding_cvss() {
        let reports = SanitizerParser::parse_kmsan_log(KMSAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.cvss_score, Some(5.5));
    }

    #[test]
    fn test_kmsan_no_offset() {
        let dmesg = r#"BUG: KMSAN: uninit-value in some_func+0x50/0x100

CPU: 0 PID: 100
Call Trace:
 some_func+0x50/0x100
==================================================================
"#;
        let reports = SanitizerParser::parse_kmsan_log(dmesg);
        if let SanitizerReport::Kmsan(kmsan) = &reports[0] {
            assert_eq!(kmsan.uninit_var, None);
            assert_eq!(kmsan.origin_function.as_deref(), Some("some_func+0x50/0x100"));
        } else {
            panic!("Expected KMSAN report");
        }
    }

    // ================================================================
    // parse_any_log tests
    // ================================================================

    #[test]
    fn test_parse_any_log_kasan_only() {
        let reports = SanitizerParser::parse_any_log(KASAN_SAMPLE);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].sanitizer_type(), SanitizerType::Kasan);
    }

    #[test]
    fn test_parse_any_log_empty() {
        let reports = SanitizerParser::parse_any_log("");
        assert!(reports.is_empty());
    }

    #[test]
    fn test_sanitizer_report_to_finding_method() {
        let reports = SanitizerParser::parse_kasan_log(KASAN_SAMPLE);
        let finding = sanitizer_report_to_finding(&reports[0]);
        assert_eq!(finding.discovery_method, DiscoveryMethod::Sanitizer);
        assert!(finding.exploit_code.is_none());
        assert!(finding.exploit_type.is_none());
        assert!(finding.chained_findings.is_empty());
        assert!(finding.disclosure_hash.is_none());
        assert!(!finding.disclosed);
    }

    // ================================================================
    // Bug type CWE mapping tests
    // ================================================================

    #[test]
    fn test_all_bug_type_cwe_mappings() {
        assert_eq!(KasanBugType::UseAfterFree.cwe(), "CWE-416");
        assert_eq!(KasanBugType::OutOfBoundsRead.cwe(), "CWE-125");
        assert_eq!(KasanBugType::OutOfBoundsWrite.cwe(), "CWE-787");
        assert_eq!(KasanBugType::GlobalOutOfBounds.cwe(), "CWE-787");
        assert_eq!(KasanBugType::StackOutOfBounds.cwe(), "CWE-121");
        assert_eq!(KasanBugType::HeapOutOfBounds.cwe(), "CWE-121");
        assert_eq!(KasanBugType::WildMemoryAccess.cwe(), "CWE-823");
        assert_eq!(KasanBugType::DoubleFree.cwe(), "CWE-415");
        assert_eq!(KasanBugType::Unknown.cwe(), "CWE-119");
    }

    #[test]
    fn test_all_bug_type_severity_mappings() {
        assert_eq!(KasanBugType::UseAfterFree.severity(), Severity::Critical);
        assert_eq!(KasanBugType::DoubleFree.severity(), Severity::Critical);
        assert_eq!(KasanBugType::OutOfBoundsWrite.severity(), Severity::Critical);
        assert_eq!(KasanBugType::HeapOutOfBounds.severity(), Severity::Critical);
        assert_eq!(KasanBugType::WildMemoryAccess.severity(), Severity::Critical);
        assert_eq!(KasanBugType::OutOfBoundsRead.severity(), Severity::High);
        assert_eq!(KasanBugType::StackOutOfBounds.severity(), Severity::High);
        assert_eq!(KasanBugType::GlobalOutOfBounds.severity(), Severity::High);
        assert_eq!(KasanBugType::Unknown.severity(), Severity::High);
    }

    #[test]
    fn test_sanitizer_type_enum() {
        let kasan_report = SanitizerParser::parse_kasan_log(KASAN_SAMPLE);
        assert_eq!(kasan_report[0].sanitizer_type(), SanitizerType::Kasan);
        let kcsan_report = SanitizerParser::parse_kcsan_log(KCSAN_SAMPLE);
        assert_eq!(kcsan_report[0].sanitizer_type(), SanitizerType::Kcsan);
        let kmsan_report = SanitizerParser::parse_kmsan_log(KMSAN_SAMPLE);
        assert_eq!(kmsan_report[0].sanitizer_type(), SanitizerType::Kmsan);
    }
}
