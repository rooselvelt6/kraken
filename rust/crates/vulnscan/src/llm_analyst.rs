use std::collections::HashMap;
use std::path::Path;

use api::{InputMessage, MessageRequest, ProviderClient};
use serde::{Deserialize, Serialize};

use crate::{AttackPath, Finding, Language, Severity};

/// Per-class system prompts for LLM-powered vulnerability analysis.
/// Each prompt is specialized for a specific vulnerability class.
pub const VULN_CLASS_PROMPTS: &[(&str, &str)] = &[
    (
        "sqli",
        "You are a SQL injection expert. Analyze the given code for SQL injection vulnerabilities.
Identify: raw SQL concatenation, unsanitized input in queries, ORM misuse, stored procedure injection.
For each finding provide: exact line number, vulnerable snippet, CWE (CWE-89), remediation, confidence 0.0-1.0.",
    ),
    (
        "xss",
        "You are an XSS (Cross-Site Scripting) expert. Analyze the code for XSS vulnerabilities.
Identify: innerHTML/outerHTML assignments, unsafe React dangerouslySetInnerHTML, template injection,
unsanitized URL parameters rendered directly, reflected/stored/DOM XSS.
For each finding provide: exact location, vulnerable context, CWE (CWE-79), remediation, confidence.",
    ),
    (
        "command_injection",
        "You are a command injection expert. Analyze the code for OS command injection.
Identify: unsanitized input in system/exec/popen/shell_exec, shell escaping vulnerabilities,
unsafe subprocess with user input, argument injection via filenames.
For each finding provide: location, vulnerable call, CWE (CWE-78), remediation, confidence.",
    ),
    (
        "crypto",
        "You are a cryptography expert. Analyze the code for cryptographic weaknesses.
Identify: weak algorithms (MD4/MD5/SHA1/RC2/RC4/DES), ECB mode, non-constant-time comparisons,
hardcoded keys/IVs, weak key derivation, insufficient entropy, improper certificate validation.
For each finding provide: location, algorithm/construct, CWE (CWE-327), remediation, confidence.",
    ),
    (
        "memory_safety",
        "You are a memory safety expert. Analyze the code for memory corruption vulnerabilities.
Identify: buffer overflows, use-after-free, double-free, integer overflows in allocations,
unchecked pointer arithmetic, unsafe Rust blocks with pointer dereferences, format string bugs.
For each finding provide: location, vulnerable operation, CWE (CWE-120/CWE-416/CWE-415),
remediation, confidence.",
    ),
    (
        "logic",
        "You are a logic flaw expert. Analyze the code for business logic vulnerabilities.
Identify: authentication bypass, authorization flaws (IDOR), race conditions (TOCTOU),
improper input validation, insecure direct object references, CSRF, SSRF, path traversal.
For each finding provide: location, logic flaw description, CWE (CWE-287/CWE-639/CWE-352),
remediation, confidence.",
    ),
    (
        "auth_bypass",
        "You are an authentication/authorization expert. Analyze the code for access control flaws.
Identify: missing authentication checks, weak password policies, JWT/ token validation flaws,
session fixation, improper role checks, insecure password reset, OAuth misconfiguration.
For each finding provide: location, flaw type, CWE (CWE-287/CWE-384), remediation, confidence.",
    ),
    (
        "kernel_memory",
        "You are a Linux/BSD kernel memory corruption expert. Analyze the kernel-level C code for:
- Use-after-free: kfree()/kfree_sensitive() followed by pointer dereference, RCU UAF, credential struct UAF
- Out-of-bounds: copy_from_user/copy_to_user without size validation, kmalloc with user-controlled size, buffer overflow in ioctl handlers, __user pointer misuse
- Double fetch: userspace memory read twice without access_ok() between, TOCTOU on shared memory
- Double free: multiple kfree() on same pointer, missing nulling after kfree
- Integer overflow: kmalloc() with size computed from user input, array index overflow
- Kernel stack overflow: large stack buffers, alloca() in interrupt context, recursive calls
- Format string: printk() with user-controlled format argument
Reference kernel APIs: kmalloc, kfree, copy_from_user, __user, access_ok, put_user, get_user, RCU, kref, mutex_lock, spin_lock, atomic_t, struct file_operations.
For each finding: CWE-416/CWE-787/CWE-120/CWE-415/CWE-190/CWE-476, remediation with kernel-specific advice.",
    ),
    (
        "kernel_race",
        "You are a Linux/BSD kernel concurrency expert. Analyze the kernel-level C code for race conditions:
- Missing lock: shared struct field access without mutex/spinlock/RCU protection
- Double lock: ABBA deadlock, nested lock acquisition in wrong order
- Lock bypass: accessing data after unlock but before re-acquiring lock
- TOCTOU: check-then-use with gap where another thread can modify state
- RCU misuse: accessing RCU-protected data outside read-side critical section, missing rcu_dereference()
- Atomicity violation: non-atomic read-modify-write on shared counter/bitfield
- seqlock imbalance: missing write_seqlock/write_sequnlock in writer path
- wait queue races: wake_up() before prepare_to_wait(), missing memory barriers
- Reference count: kref get/put imbalance, credential refcount overflow
Reference kernel APIs: spin_lock, mutex_lock, rcu_read_lock, rcu_dereference, seqlock_t, atomic_t, kref_get, kref_put, wait_queue_head_t, smp_mb().
For each finding: CWE-362/CWE-667/CWE-821, provide exact race window and suggested fix.",
    ),
    (
        "kernel_info_leak",
        "You are a Linux/BSD kernel information disclosure expert. Analyze for kernel memory leaks:
- copy_to_user without bounds: copying uninitialized kernel stack/heap to userspace
- Uninitialized struct padding: stack struct with padding bytes not zeroed before copy
- dmesg leaks: kernel addresses in printk() output exposed via dmesg_restrict bypass
- /proc/ leaks: exposing kernel pointers via /proc filesystem, kallsyms without kptr_restrict
- sysfs attribute leaks: exposing sensitive kernel state via sysfs files
- KASLR bypass: kernel text addresses leaked via side channels, error messages, function pointers
- kmalloc uninit: using kmalloc() instead of kzalloc(), heap content exposed to userspace
- seq_file leaks: seq_printf with sensitive data, /proc/pid/maps exposing addresses
- speculative side channels: KASLR bypass via prefetch timing, cache timing
Reference kernel APIs: copy_to_user, kzalloc, kfree, seq_printf, proc_create, sysfs_create_file, kallsyms, dmesg.
For each finding: CWE-200/CWE-203/CWE-402, provide the exact leak path and remediation.",
    ),
    (
        "kernel_priv_esc",
        "You are a Linux/BSD privilege escalation expert. Analyze kernel code for escalation vectors:
- ioctl handlers: unlocked_ioctl without proper privilege check, allowing arbitrary hardware access
- BPF: eBPF program verifier bypass, arbitrary kernel memory read/write via crafted BPF
- Filesystem: overlayfs mount escape, FUSE privilege escalation, filesystem type confusion
- Capabilities: missing cap_capable() check, capability bypass via user namespaces
- User namespaces: unprivileged user_ns creation allowing access to otherwise-restricted interfaces
- modprobe_path: controlling modprobe_path via binfmt_misc or other interfaces
- core_pattern: arbitrary executable execution via /proc/sys/kernel/core_pattern
- Module loading: unsigned module loading with CONFIG_MODULE_SIG disabled, module_request bypass
- Security bypass: LSM bypass via crafted arguments, SELinux/AppArmor context confusion
- Keyring: kernel keyring overflow, keyctl privilege escalation
- Syscall: missing syscall number validation in compat mode, syscall table manipulation
For each finding: CWE-269/CWE-250/CWE-276, provide escalation path, prerequisites for unprivileged user, and kernel version range if applicable.",
    ),
];

/// A lightweight finding produced by LLM analysis, tied back to a scanner finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmValidation {
    pub finding_id: String,
    pub validated: bool,
    pub confidence: f32,
    pub cvss_score: Option<f32>,
    pub explanation: String,
    pub remediation: Option<String>,
}

/// Configuration for the LLM analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalystConfig {
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub enabled_classes: Vec<String>,
}

impl Default for LlmAnalystConfig {
    fn default() -> Self {
        Self {
            model: "deepseek/deepseek-chat".to_string(),
            temperature: 0.3,
            max_tokens: 4096,
            enabled_classes: vec![
                "sqli".into(),
                "xss".into(),
                "command_injection".into(),
                "crypto".into(),
                "memory_safety".into(),
                "kernel_memory".into(),
                "kernel_race".into(),
                "kernel_info_leak".into(),
                "kernel_priv_esc".into(),
                "logic".into(),
                "auth_bypass".into(),
            ],
        }
    }
}

/// LLM-powered vulnerability analyst that cross-validates scanner findings
/// using per-class system prompts and generates exploit primitives.
pub struct LlmAnalyst {
    config: LlmAnalystConfig,
    provider: ProviderClient,
    class_prompt_map: HashMap<String, String>,
}

impl LlmAnalyst {
    pub fn new(config: LlmAnalystConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = ProviderClient::from_model(&config.model)?;
        let class_prompt_map: HashMap<String, String> = VULN_CLASS_PROMPTS
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Ok(Self {
            config,
            provider,
            class_prompt_map,
        })
    }

    /// Cross-validate scanner findings against the LLM with class-specific prompts.
    /// Groups findings by vulnerability class, sends code + findings to LLM,
    /// and returns validated findings with updated confidence scores.
    pub async fn cross_validate(
        &self,
        _file_path: &Path,
        content: &str,
        language: Language,
        findings: &[Finding],
    ) -> Vec<LlmValidation> {
        if findings.is_empty() || content.len() > 100_000 {
            return vec![];
        }

        let mut validations = Vec::new();

        for class in &self.config.enabled_classes {
            let class_findings: Vec<&Finding> = findings
                .iter()
                .filter(|f| self.matches_class(f, class))
                .collect();

            if class_findings.is_empty() {
                continue;
            }

            let prompt = self.build_class_prompt(class, content, language, &class_findings);
            match self.call_llm(&prompt).await {
                Ok(response) => {
                    let parsed = self.parse_validation_response(&response, &class_findings);
                    validations.extend(parsed);
                }
                Err(e) => {
                    eprintln!("[llm_analyst] class '{class}' LLM call failed: {e}");
                }
            }
        }

        validations
    }

    /// Rank findings by exploitability probability using the LLM.
    pub async fn rank_findings(&self, findings: &[Finding]) -> Vec<(usize, f32)> {
        if findings.is_empty() {
            return vec![];
        }

        let descriptions: Vec<String> = findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                format!(
                    "[{i}] {desc} (CWE: {cwe}, Severity: {sev})",
                    desc = f.description,
                    cwe = f.cwe.as_deref().unwrap_or("N/A"),
                    sev = format_args!("{:?}", f.severity),
                )
            })
            .collect();

        let prompt = format!(
            "Rate each security finding's exploitability likelihood (0.0-1.0).
Respond with ONLY a JSON array of floats: [0.0, 0.5, ...]

Findings:
{}",
            descriptions.join("\n")
        );

        let mut rankings: Vec<(usize, f32)> = findings.iter().enumerate().map(|(i, _)| (i, 0.5)).collect();

        match self.call_llm(&prompt).await {
            Ok(response) => {
                if let Ok(scores) = serde_json::from_str::<Vec<f64>>(&response) {
                    for (i, score) in scores.iter().enumerate() {
                        if i < rankings.len() {
                            rankings[i].1 = (*score as f32).clamp(0.0, 1.0);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[llm_analyst] ranking LLM call failed: {e}");
            }
        }

        rankings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        rankings
    }

    /// Generate exploit primitives (PoC code) for a validated finding.
    pub async fn generate_exploit_primitive(&self, finding: &Finding) -> Option<String> {
        let class = self.class_for_finding(finding);
        let class_prompt = self
            .class_prompt_map
            .get(class)
            .map(|s| s.as_str())
            .unwrap_or("You are an exploit developer. Generate working PoC code.");

        let prompt = format!(
            "{}

Generate a working PoC exploit for this vulnerability. Respond with ONLY valid JSON:
{{ \"language\": \"python|ruby|bash|javascript\",
  \"code\": \"... properly escaped PoC code ...\",
  \"type\": \"RCE|PrivEsc|DoS|AuthBypass|InfoLeak\",
  \"prerequisites\": \"...\",
  \"notes\": \"...\" }}

Finding:
- Description: {}
- CWE: {:?}
- Severity: {:?}
- File: {:?}:{}",
            class_prompt,
            finding.description,
            finding.cwe,
            finding.severity,
            finding.file_path,
            finding.line_number.unwrap_or(0),
        );

        match self.call_llm(&prompt).await {
            Ok(response) => {
                let cleaned = response
                    .trim()
                    .trim_start_matches("```json")
                    .trim_start_matches("```")
                    .trim_end_matches("```")
                    .trim();
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(cleaned) {
                    val.get("code").and_then(|c| c.as_str()).map(|s| s.to_string())
                } else {
                    Some(response)
                }
            }
            Err(e) => {
                eprintln!("[llm_analyst] exploit gen LLM call failed: {e}");
                None
            }
        }
    }

    /// Generate a human-readable bughunt summary from findings and attack paths.
    pub async fn generate_bughunt_summary(
        &self,
        findings: &[Finding],
        attack_paths: &[AttackPath],
    ) -> String {
        let high_risk: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.severity == Severity::Critical || f.severity == Severity::High
            })
            .collect();

        let paths_text: Vec<String> = attack_paths
            .iter()
            .map(|p| {
                format!(
                    "- Path: {} (likelihood: {:.2}, severity: {:?}, {} steps)",
                    p.description, p.total_likelihood, p.max_severity, p.steps
                )
            })
            .collect();

        let prompt = format!(
            "Summarize this security assessment in a clear, actionable report.

HIGH/CRITICAL FINDINGS ({count}):
{findings}

ATTACK PATHS:
{paths}

Format as a concise report with: key risks, recommended fixes priority, attack chain overview.",
            count = high_risk.len(),
            findings = high_risk
                .iter()
                .map(|f| {
                    let sev = format!("{:?}", f.severity);
                    let desc = &f.description;
                    let path = &f.file_path;
                    let line = f.line_number.unwrap_or(0);
                    format!("- [{sev}] {desc} at {path:?}:{line}")
                })
                .collect::<Vec<_>>()
                .join("\n"),
            paths = paths_text.join("\n"),
        );

        match self.call_llm(&prompt).await {
            Ok(response) => response,
            Err(e) => {
                format!("[Bughunt summary generation failed: {e}]")
            }
        }
    }

    fn class_for_finding<'a>(&self, finding: &'a Finding) -> &'a str {
        class_for_finding(finding)
    }

    fn matches_class(&self, finding: &Finding, class: &str) -> bool {
        matches_class(finding, class)
    }

    fn build_class_prompt(
        &self,
        class: &str,
        content: &str,
        language: Language,
        findings: &[&Finding],
    ) -> String {
        let class_prompt = self
            .class_prompt_map
            .get(class)
            .map(|s| s.as_str())
            .unwrap_or("Analyze the code for security vulnerabilities.");

        let findings_text: Vec<String> = findings
            .iter()
            .map(|f| {
                format!(
                    "- [{sev}] Line {line}: {desc} (CWE: {cwe})",
                    sev = format_args!("{:?}", f.severity),
                    line = f.line_number.unwrap_or(0),
                    desc = f.description,
                    cwe = f.cwe.as_deref().unwrap_or("N/A"),
                )
            })
            .collect();

        let truncated: String = content.chars().take(30_000).collect();

        format!(
            "{class_prompt}

## Scanner Findings for Review
{findings}

## Code
```{lang}
{code}
```

## Task
Review the scanner findings against the actual code. For each finding, respond with a JSON array:
[{{ \"index\": 0, \"valid\": true/false, \"confidence\": 0.0-1.0,
   \"cvss_score\": 0.0-10.0, \"explanation\": \"...\",
   \"remediation\": \"...\" }}]

Mark a finding as INVALID if it is a false positive (wrong context, mitigated, not exploitable).
Adjust confidence and CVSS based on actual code context.",
            class_prompt = class_prompt,
            findings = findings_text.join("\n"),
            lang = format!("{:?}", language).to_lowercase(),
            code = truncated,
        )
    }

    async fn call_llm(
        &self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let request = MessageRequest {
            model: self.config.model.clone(),
            max_tokens: self.config.max_tokens,
            temperature: Some(self.config.temperature as f64),
            messages: vec![InputMessage::user_text(prompt)],
            system: None,
            ..Default::default()
        };
        let response = self.provider.send_message(&request).await?;
        let text: Vec<String> = response
            .content
            .iter()
            .filter_map(|block| match block {
                api::OutputContentBlock::Text { text } => Some(text.clone()),
                _ => None,
            })
            .collect();
        Ok(text.join("\n"))
    }

    fn parse_validation_response(
        &self,
        response: &str,
        findings: &[&Finding],
    ) -> Vec<LlmValidation> {
        let json_str = extract_json_array(response).unwrap_or(response);
        let mut validations = Vec::new();

        if let Ok(array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
            for item in &array {
                let index = item.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if index >= findings.len() {
                    continue;
                }
                let finding = findings[index];
                let validated = item
                    .get("valid")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                validations.push(LlmValidation {
                    finding_id: finding.id.clone(),
                    validated,
                    confidence: item
                        .get("confidence")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32,
                    cvss_score: item.get("cvss_score").and_then(|v| v.as_f64().map(|s| s as f32)),
                    explanation: item
                        .get("explanation")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    remediation: item
                        .get("remediation")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                });
            }
        }

        validations
    }
}

/// Output of the full LLM analysis and bughunt pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalysisReport {
    pub validations: Vec<LlmValidation>,
    pub rankings: Vec<(usize, f32)>,
    pub exploit_primitives: Vec<(String, String)>,
    pub bughunt_summary: String,
}

/// Map a finding to its vulnerability class based on CWE.
///
/// # Examples
///
/// ```
/// use vulnscan::{Finding, Severity, DiscoveryMethod};
/// use vulnscan::llm_analyst::class_for_finding;
/// let f = Finding::new(Severity::High, "sqli", None, None, None, None, Some("CWE-89".to_string()), 0.9, DiscoveryMethod::StaticPatternMatching);
/// assert_eq!(class_for_finding(&f), "sqli");
/// ```
pub fn class_for_finding(finding: &Finding) -> &str {
    match finding.cwe.as_deref() {
        Some(cwe) if cwe.contains("89") => "sqli",
        Some(cwe) if cwe.contains("79") => "xss",
        Some(cwe) if cwe.contains("78") => "command_injection",
        Some(cwe) if cwe.contains("327") | cwe.contains("338") => "crypto",
        Some(cwe) if cwe.contains("120") | cwe.contains("416") | cwe.contains("415") | cwe.contains("190") => {
            if finding.file_path.as_ref().is_some_and(|p| {
                let s = p.to_string_lossy();
                s.contains("/kernel/") || s.contains("/drivers/") || s.contains("/arch/")
                    || s.contains("/fs/") || s.contains("/net/") || s.contains("/include/linux/")
                    || s.contains("/mm/") || s.contains("/security/")
            }) {
                "kernel_memory"
            } else {
                "memory_safety"
            }
        }
        Some(cwe) if cwe.contains("362") || cwe.contains("667") || cwe.contains("821") => {
            if finding.file_path.as_ref().is_some_and(|p| {
                let s = p.to_string_lossy();
                s.contains("/kernel/") || s.contains("/drivers/")
            }) {
                "kernel_race"
            } else {
                "logic"
            }
        }
        Some(cwe) if cwe.contains("200") || cwe.contains("203") || cwe.contains("402") => {
            if finding.file_path.as_ref().is_some_and(|p| {
                let s = p.to_string_lossy();
                s.contains("/kernel/") || s.contains("/drivers/")
            }) {
                "kernel_info_leak"
            } else {
                "logic"
            }
        }
        Some(cwe) if cwe.contains("269") || cwe.contains("250") || cwe.contains("276") => {
            if finding.file_path.as_ref().is_some_and(|p| {
                let s = p.to_string_lossy();
                s.contains("/kernel/") || s.contains("/drivers/")
            }) {
                "kernel_priv_esc"
            } else {
                "logic"
            }
        }
        Some(cwe) if cwe.contains("287") | cwe.contains("384") => "auth_bypass",
        Some(cwe) if cwe.contains("639") | cwe.contains("352") | cwe.contains("918") => "logic",
        _ => "logic",
    }
}

/// Check if a finding belongs to a specific vulnerability class.
///
/// # Examples
///
/// ```
/// use vulnscan::{Finding, Severity, DiscoveryMethod};
/// use vulnscan::llm_analyst::matches_class;
/// let f = Finding::new(Severity::High, "xss", None, None, None, None, Some("CWE-79".to_string()), 0.9, DiscoveryMethod::StaticPatternMatching);
/// assert!(matches_class(&f, "xss"));
/// assert!(!matches_class(&f, "sqli"));
/// ```
pub fn matches_class(finding: &Finding, class: &str) -> bool {
    class_for_finding(finding) == class
}

fn extract_json_array(text: &str) -> Option<&str> {
    if let Some(start) = text.find('[') {
        let mut depth = 0;
        for (i, ch) in text[start..].char_indices() {
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&text[start..=start + i]);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_for_finding_sqli() {
        let finding = Finding {
            cwe: Some("CWE-89".into()),
            description: "SQL injection".into(),
            ..Default::default()
        };
        assert_eq!(class_for_finding(&finding), "sqli");
    }

    #[test]
    fn test_class_for_finding_xss() {
        let finding = Finding {
            cwe: Some("CWE-79".into()),
            ..Default::default()
        };
        assert_eq!(class_for_finding(&finding), "xss");
    }

    #[test]
    fn test_class_for_finding_memory() {
        let f1 = Finding {
            cwe: Some("CWE-120".into()),
            ..Default::default()
        };
        let f2 = Finding {
            cwe: Some("CWE-416".into()),
            ..Default::default()
        };
        assert_eq!(class_for_finding(&f1), "memory_safety");
        assert_eq!(class_for_finding(&f2), "memory_safety");
    }

    #[test]
    fn test_class_for_finding_fallback() {
        let finding = Finding {
            cwe: Some("CWE-999".into()),
            ..Default::default()
        };
        assert_eq!(class_for_finding(&finding), "logic");
    }

    #[test]
    fn test_parse_validation_response() {
        let config = LlmAnalystConfig::default();
        let provider = ProviderClient::from_model(&config.model);
        if provider.is_err() {
            eprintln!("Skipping test: no API credentials");
            return;
        }
        let analyst = LlmAnalyst::new(config).unwrap();
        let findings = vec![
            Finding {
                id: "abc-123".into(),
                description: "test finding".into(),
                ..Default::default()
            },
        ];
        let response = r#"[
            {"index": 0, "valid": true, "confidence": 0.85, "cvss_score": 7.5,
             "explanation": "Valid SQL injection", "remediation": "Use parameterized queries"}
        ]"#;
        let refs: Vec<&Finding> = findings.iter().collect();
        let validations = analyst.parse_validation_response(response, &refs);
        assert_eq!(validations.len(), 1);
        assert!(validations[0].validated);
        assert_eq!(validations[0].finding_id, "abc-123");
        assert!((validations[0].confidence - 0.85).abs() < 0.01);
        assert_eq!(validations[0].cvss_score, Some(7.5));
    }

    #[test]
    fn test_parse_validation_out_of_bounds() {
        let config = LlmAnalystConfig::default();
        let provider = ProviderClient::from_model(&config.model);
        if provider.is_err() {
            eprintln!("Skipping test: no API credentials");
            return;
        }
        let analyst = LlmAnalyst::new(config).unwrap();
        let response = r#"[
            {"index": 0, "valid": false, "confidence": 0.0, "explanation": "FP"}
        ]"#;
        let validations = analyst.parse_validation_response(response, &[]);
        assert!(validations.is_empty());
    }

    #[test]
    fn test_vuln_class_prompts_are_unique() {
        let mut names = std::collections::HashSet::new();
        for (name, _) in VULN_CLASS_PROMPTS {
            assert!(names.insert(name), "Duplicate class name: {name}");
        }
        assert_eq!(names.len(), VULN_CLASS_PROMPTS.len());
    }

    #[test]
    fn test_extract_json_array() {
        let text = "Some text before\n[{\"key\": \"value\"}]\nsome after";
        let extracted = extract_json_array(text).unwrap();
        assert_eq!(extracted, "[{\"key\": \"value\"}]");
    }

    #[test]
    fn test_extract_json_array_no_array() {
        assert!(extract_json_array("no brackets here").is_none());
    }

    #[test]
    fn test_matches_class() {
        let f = Finding {
            cwe: Some("CWE-78".into()),
            ..Default::default()
        };
        assert!(matches_class(&f, "command_injection"));
        assert!(!matches_class(&f, "xss"));
    }
}
