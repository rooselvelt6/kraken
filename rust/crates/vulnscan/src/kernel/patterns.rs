use crate::{DiscoveryMethod, Finding, Severity};
use std::path::Path;

pub struct KernelPatternAnalyzer;

impl KernelPatternAnalyzer {
    pub fn analyze(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Ok(parsed) = Self::parse_with_tree_sitter(content) {
            findings.extend(Self::check_copy_from_user(content, &parsed, file_path));
            findings.extend(Self::check_copy_to_user(content, &parsed, file_path));
            findings.extend(Self::check_kmalloc(content, &parsed, file_path));
            findings.extend(Self::check_ioctl_handler(content, &parsed, file_path));
            findings.extend(Self::check_procfs_locks(content, &parsed, file_path));
            findings.extend(Self::check_double_fetch(content, &parsed, file_path));
            findings.extend(Self::check_stack_buf(content, &parsed, file_path));
            findings.extend(Self::check_null_deref(content, &parsed, file_path));
        }

        findings
    }

    fn parse_with_tree_sitter(content: &str) -> Result<(), ()> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c::LANGUAGE.into();
        parser.set_language(&lang).map_err(|_| ())?;
        let tree = parser.parse(content, None).ok_or(())?;
        let root = tree.root_node();
        if root.has_error() {
            return Err(());
        }
        Ok(())
    }

    fn find_lines_containing(content: &str, patterns: &[&str]) -> Vec<(usize, String)> {
        let mut results = Vec::new();
        for (i, line) in content.lines().enumerate() {
            for pat in patterns {
                if line.contains(pat) {
                    results.push((i, line.trim().to_string()));
                    break;
                }
            }
        }
        results
    }

    fn check_copy_from_user(
        content: &str,
        _parsed: &(),
        file_path: &Path,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in Self::find_lines_containing(
            content,
            &["copy_from_user", "__copy_from_user", "raw_copy_from_user"],
        ) {
            if !line.contains("sizeof") && !line.contains(">=") && !line.contains("<=")
                && !line.contains("min(") && !line.contains("max(")
                && !line.contains("check")
            {
                findings.push(Self::make_finding(
                    "copy_from_user without size validation — potential kernel heap overflow",
                    "CWE-120",
                    Severity::Critical,
                    i,
                    &line,
                    file_path,
                    "Validate the size argument: add bounds check (size > max_bytes) before copy_from_user, or use min(size, max_bytes)",
                ));
            }
        }
        findings
    }

    fn check_copy_to_user(
        content: &str,
        _parsed: &(),
        file_path: &Path,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in Self::find_lines_containing(content, &["copy_to_user", "__copy_to_user"]) {
            if !line.contains("sizeof") && !line.contains(">=") && !line.contains("<=")
                && !line.contains("min(") && !line.contains("kzalloc")
                && !line.contains("zero")
            {
                findings.push(Self::make_finding(
                    "copy_to_user may leak uninitialized kernel memory",
                    "CWE-200",
                    Severity::High,
                    i,
                    &line,
                    file_path,
                    "Zero-fill the buffer (kzalloc) before copy_to_user, or ensure all struct padding is initialized",
                ));
            }
        }
        findings
    }

    fn check_kmalloc(_content: &str, _parsed: &(), file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = file_path.to_string_lossy();
        if path_str.contains("ioctl") || path_str.contains("dev_") || path_str.contains("driver") {
            findings.push(Self::make_finding(
                "Device driver found — verify kmalloc sizes are not user-controlled",
                "CWE-190",
                Severity::Medium,
                0,
                "",
                file_path,
                "Ensure all kmalloc/kvmalloc size arguments are bounded, not taken directly from userspace",
            ));
        }
        findings
    }

    fn check_ioctl_handler(_content: &str, _parsed: &(), file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = file_path.to_string_lossy();
        if (path_str.contains("ioctl") || path_str.ends_with("_ioctl.c"))
            && !_content.contains("unlocked_ioctl") && !_content.contains("compat_ioctl")
        {
            findings.push(Self::make_finding(
                "No unlocked_ioctl handler found in ioctl-related file",
                "CWE-269",
                Severity::Medium,
                0,
                "",
                file_path,
                "Implement unlocked_ioctl or compat_ioctl in struct file_operations, with proper privilege checks",
            ));
        }
        findings
    }

    fn check_procfs_locks(_content: &str, _parsed: &(), file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = file_path.to_string_lossy();
        if path_str.contains("/proc/") || path_str.contains("procfs") {
            findings.push(Self::make_finding(
                "procfs file — verify seq_file operations have proper locking",
                "CWE-667",
                Severity::Medium,
                0,
                "",
                file_path,
                "Add mutex or RCU locks around seq_operations show/next/stop callbacks to prevent race conditions",
            ));
        }
        findings
    }

    fn check_double_fetch(content: &str, _parsed: &(), file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("copy_from_user") && !trimmed.contains("get_user") {
                continue;
            }
            for j in (i + 1)..lines.len().min(i + 15) {
                let next = lines[j].trim();
                if (next.contains("copy_from_user") || next.contains("get_user"))
                    && !next.starts_with("//") && !next.starts_with("/*")
                {
                    findings.push(Self::make_finding(
                        "Potential double fetch — userspace value read twice without access_ok between fetches",
                        "CWE-367",
                        Severity::High,
                        i,
                        trimmed,
                        file_path,
                        "Read userspace data once into kernel buffer, validate it, then use the kernel copy. Do not re-read from userspace.",
                    ));
                    break;
                }
            }
        }
        findings
    }

    fn check_stack_buf(_content: &str, _parsed: &(), file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = file_path.to_string_lossy();
        if path_str.contains("/drivers/") || path_str.contains("/sound/") {
            findings.push(Self::make_finding(
                "Potential stack buffer — verify stack buffers in this file have bounded sizes",
                "CWE-121",
                Severity::Medium,
                0,
                "",
                file_path,
                "Use kmalloc for large buffers (> 256 bytes), avoid alloca() in interrupt context, check recursion depth",
            ));
        }
        findings
    }

    fn check_null_deref(content: &str, _parsed: &(), file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for func in &["kmalloc", "kzalloc", "kcalloc", "kvmalloc"] {
                if trimmed.contains(func) && trimmed.contains("=")
                    && !trimmed.to_lowercase().contains("null")
                    && !trimmed.contains("if (")
                {
                    let next_10: Vec<&str> = content.lines().skip(i + 1).take(10).collect();
                    let has_check = next_10.iter().any(|l| {
                        let t = l.trim();
                        t.contains("if (") && (t.contains("NULL") || t.contains("null")
                            || t.contains("!") || t.contains("error") || t.contains("ret"))
                    });
                    if !has_check {
                        findings.push(Self::make_finding(
                            format!("{} result not checked for NULL before use", func),
                            "CWE-476",
                            Severity::High,
                            i,
                            trimmed,
                            file_path,
                            format!("Check {}() return value for NULL: `if (!ptr) return -ENOMEM;`", func),
                        ));
                    }
                    break;
                }
            }
        }
        findings
    }

    fn make_finding(
        description: impl Into<String>,
        cwe: &str,
        severity: Severity,
        line_num: usize,
        snippet: impl Into<String>,
        file_path: &Path,
        remediation: impl Into<String>,
    ) -> Finding {
        Finding {
            id: crate::new_finding_id(),
            severity,
            cwe: Some(cwe.to_string()),
            cve: None,
            description: description.into(),
            file_path: Some(file_path.to_path_buf()),
            line_number: Some(line_num as u32 + 1),
            vulnerable_code_snippet: Some(snippet.into()),
            remediation: Some(remediation.into()),
            confidence: 0.7,
            discovery_method: DiscoveryMethod::StaticPatternMatching,
            exploit_code: None,
            exploit_type: None,
            chained_findings: vec![],
            poc_validated: false,
            status: crate::FindingStatus::Open,
            cvss_score: Some(match severity {
                Severity::Critical => 9.0,
                Severity::High => 7.0,
                Severity::Medium => 5.0,
                Severity::Low => 3.0,
                Severity::Info => 1.0,
            }),
            severity_confidence: 0.7,
            discovered_at: chrono::Utc::now(),
            disclosed: false,
            disclosure_hash: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_copy_from_user_no_size_check() {
        let content = "ret = copy_from_user(buf, arg, size);\n";
        let p = PathBuf::from("/kernel/drivers/test.c");
        let findings = KernelPatternAnalyzer::analyze(content, &p);
        assert!(findings.iter().any(|f| f.description.contains("copy_from_user")));
    }

    #[test]
    fn test_copy_from_user_with_sizeof() {
        let content = "void func(void) { ret = copy_from_user(buf, arg, sizeof(struct foo)); }\n";
        let p = PathBuf::from("/kernel/drivers/test.c");
        let findings = KernelPatternAnalyzer::analyze(content, &p);
        let cwe120: Vec<&Finding> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.is_empty(), "sizeof should suppress the finding");
    }

    #[test]
    fn test_kmalloc_no_null_check() {
        let content = "ptr = kmalloc(size, GFP_KERNEL);\nptr->field = 1;\n";
        let p = PathBuf::from("/kernel/drivers/test.c");
        let findings = KernelPatternAnalyzer::analyze(content, &p);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-476")));
    }

    #[test]
    fn test_kmalloc_with_null_check() {
        let content = "ptr = kmalloc(size, GFP_KERNEL);\nif (!ptr) return -ENOMEM;\nptr->field = 1;\n";
        let p = PathBuf::from("/kernel/drivers/test.c");
        let findings = KernelPatternAnalyzer::analyze(content, &p);
        let null_derefs: Vec<&Finding> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-476")).collect();
        assert!(null_derefs.is_empty());
    }

    #[test]
    fn test_double_fetch_detected() {
        let content = "void func(void) {\n    get_user(val, arg);\n    int x = 1;\n    get_user(val, arg);\n}\n";
        let p = PathBuf::from("/kernel/drivers/test.c");
        let findings = KernelPatternAnalyzer::analyze(content, &p);
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-367")));
    }

    #[test]
    fn test_tree_sitter_parse_valid_c() {
        let content = "int foo(void) { return 0; }\n";
        assert!(KernelPatternAnalyzer::parse_with_tree_sitter(content).is_ok());
    }

    #[test]
    fn test_tree_sitter_parse_empty() {
        let content = "";
        assert!(KernelPatternAnalyzer::parse_with_tree_sitter(content).is_ok());
    }
}
