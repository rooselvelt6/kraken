use std::collections::{HashMap, VecDeque};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolCallDigest {
    /// Hash of (`tool_name`, `arg_hash`)
    pub digest: [u8; 32],
    pub tool_name: String,
}

#[derive(Debug, Clone)]
pub struct ToolCallFingerprinter {
    /// Rolling window of recent tool call digests
    window: VecDeque<ToolCallDigest>,
    /// Maximum window size
    max_window: usize,
    /// Frequency map for pattern detection
    freq: HashMap<[u8; 32], u32>,
}

impl ToolCallFingerprinter {
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            max_window: window_size,
            freq: HashMap::new(),
        }
    }

    pub fn record_call(&mut self, tool_name: &str, arg_hash: &[u8]) -> ToolCallDigest {
        let digest = compute_digest(tool_name, arg_hash);

        if self.window.len() >= self.max_window {
            if let Some(removed) = self.window.pop_front() {
                if let Some(count) = self.freq.get_mut(&removed.digest) {
                    *count -= 1;
                    if *count == 0 {
                        self.freq.remove(&removed.digest);
                    }
                }
            }
        }

        *self.freq.entry(digest.digest).or_insert(0) += 1;
        self.window.push_back(digest.clone());
        digest
    }

    /// Returns true if the same tool+arg pattern appears more than `threshold` times in the window.
    #[must_use]
    pub fn is_repetitive(&self, tool_name: &str, arg_hash: &[u8]) -> bool {
        let digest = compute_digest(tool_name, arg_hash);
        self.freq.get(&digest.digest).copied().unwrap_or(0) > 3
    }

    /// Detect reconnaissance patterns: read many different files in succession.
    #[must_use]
    pub fn detect_recon(&self) -> bool {
        if self.window.len() < 5 {
            return false;
        }
        let read_calls = self
            .window
            .iter()
            .filter(|d| d.tool_name.contains("read") || d.tool_name == "Read")
            .count();
        let unique = self
            .window
            .iter()
            .map(|d| &d.digest)
            .collect::<std::collections::HashSet<_>>()
            .len();

        // Many reads of unique files = potential recon
        #[allow(clippy::cast_precision_loss)]
        {
            read_calls >= 5 && unique as f64 / self.window.len() as f64 > 0.7
        }
    }

    /// Detect scanning pattern: glob then read pattern.
    #[must_use]
    pub fn detect_scan_chain(&self) -> bool {
        if self.window.len() < 4 {
            return false;
        }
        let recent: Vec<&str> = self.window.iter().map(|d| d.tool_name.as_str()).collect();
        recent.windows(2).any(|w| {
            (w[0].contains("glob") || w[0].contains("Glob"))
                && (w[1].contains("read") || w[1].contains("Read"))
        })
    }

    /// Detect exfiltration pattern: many consecutive reads of large files.
    #[must_use]
    pub fn detect_exfil(&self) -> bool {
        if self.window.len() < 10 {
            return false;
        }
        let read_calls = self
            .window
            .iter()
            .filter(|d| d.tool_name.contains("read") || d.tool_name == "Read")
            .count();
        let tool_calls = self
            .window
            .iter()
            .filter(|d| d.tool_name.contains("bash") || d.tool_name == "Bash")
            .count();

        // Many reads with few tool calls = exfil pattern
        read_calls >= 8 && tool_calls == 0
    }

    /// Return the current window of digests
    #[must_use]
    pub fn window(&self) -> &VecDeque<ToolCallDigest> {
        &self.window
    }

    /// Clear the window
    pub fn reset(&mut self) {
        self.window.clear();
        self.freq.clear();
    }
}

impl Default for ToolCallFingerprinter {
    fn default() -> Self {
        Self::new(20)
    }
}

fn compute_digest(tool_name: &str, arg_hash: &[u8]) -> ToolCallDigest {
    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update(arg_hash);
    let digest = hasher.finalize().into();
    ToolCallDigest {
        digest,
        tool_name: tool_name.to_string(),
    }
}

#[must_use]
pub fn hash_arguments(args: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(args.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_tracks_calls() {
        let mut fp = ToolCallFingerprinter::new(10);
        let args = hash_arguments("ls -la");
        fp.record_call("bash", &args);
        assert_eq!(fp.window().len(), 1);
    }

    #[test]
    fn detects_repetitive_calls() {
        let mut fp = ToolCallFingerprinter::new(10);
        let args = hash_arguments("cat /etc/passwd");
        for _ in 0..5 {
            fp.record_call("read_file", &args);
        }
        assert!(fp.is_repetitive("read_file", &args));
    }

    #[test]
    fn detects_recon_pattern() {
        let mut fp = ToolCallFingerprinter::new(20);
        for i in 0..8 {
            let args = hash_arguments(&format!("file{i}.txt"));
            fp.record_call("read_file", &args);
        }
        assert!(fp.detect_recon());
    }

    #[test]
    fn detects_scan_chain() {
        let mut fp = ToolCallFingerprinter::new(20);
        fp.record_call("bash", &hash_arguments("ls"));
        fp.record_call("glob_search", &hash_arguments("*.json"));
        fp.record_call("read_file", &hash_arguments("config.json"));
        fp.record_call("read_file", &hash_arguments("data.json"));
        assert!(fp.detect_scan_chain());
    }

    #[test]
    fn does_not_false_positive_normal_use() {
        let mut fp = ToolCallFingerprinter::new(20);
        fp.record_call("bash", &hash_arguments("ls"));
        fp.record_call("bash", &hash_arguments("git status"));
        fp.record_call("read_file", &hash_arguments("src/main.rs"));
        fp.record_call("bash", &hash_arguments("cargo build"));
        assert!(!fp.detect_recon());
        assert!(!fp.detect_exfil());
    }

    #[test]
    fn reset_clears_window() {
        let mut fp = ToolCallFingerprinter::new(10);
        fp.record_call("bash", &hash_arguments("ls"));
        fp.reset();
        assert_eq!(fp.window().len(), 0);
    }
}
