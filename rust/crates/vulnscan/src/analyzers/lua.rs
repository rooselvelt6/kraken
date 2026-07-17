use crate::{DiscoveryMethod, Finding, Language, ScanConfig, Severity};
use std::path::Path;

pub struct LuaAnalyzer;

impl Default for LuaAnalyzer {
    fn default() -> Self {
        Self
    }
}

impl super::LanguageAnalyzer for LuaAnalyzer {
    fn language(&self) -> Language {
        Language::Lua
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["lua"]
    }

    fn analyze(&self, content: &str, file_path: &Path, _config: &ScanConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let lineno = i as u32 + 1;

            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }

            // Command injection: os.execute(), io.popen()
            if trimmed.contains("os.execute(") || trimmed.contains("io.popen(") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-78",
                    "OS Command Injection",
                    "Command execution via os.execute() or io.popen(). Validate and sanitize all user-controlled input. Use parameterized APIs where possible.",
                    0.9,
                ));
            }

            // Code injection: load(), loadstring(), loadfile()
            if trimmed.contains("loadstring(") || trimmed.contains("load(") && trimmed.contains(")")
            {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-94",
                    "Code Injection via load/loadstring",
                    "Dynamic code execution with load() or loadstring(). Avoid evaluating user-supplied strings as code. Use a sandbox or pre-parse inputs.",
                    0.95,
                ));
            }

            // Unsafe file inclusion: dofile(), loadfile()
            if trimmed.contains("dofile(") || trimmed.contains("loadfile(") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Medium,
                    "CWE-829",
                    "Unsafe File Inclusion",
                    "Inclusion of external files via dofile()/loadfile(). Ensure the path is not user-controlled and the file is trusted.",
                    0.8,
                ));
            }

            // Path traversal in file I/O
            if (trimmed.contains("io.open(") || trimmed.contains("file:read(") || trimmed.contains("file:write("))
                && (trimmed.contains("..") || !has_quoted_literal_path(trimmed))
            {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-22",
                    "Path Traversal in File I/O",
                    "File operations with dynamically constructed paths. Validate and sanitize all path components to prevent directory traversal.",
                    0.85,
                ));
            }

            // SQL injection via string concatenation
            if (trimmed.contains("execute(") || trimmed.contains("query(") || trimmed.contains("prepare("))
                && (trimmed.contains(" .. ") || trimmed.contains("string.format("))
            {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Critical,
                    "CWE-89",
                    "SQL Injection",
                    "SQL query constructed via string concatenation or formatting. Use parameterized queries or prepared statements.",
                    0.9,
                ));
            }

            // Hardcoded secrets
            if is_secret_assignment(trimmed) {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::High,
                    "CWE-798",
                    "Hardcoded Secret",
                    "Hardcoded credential or secret detected. Use environment variables or a secure vault instead.",
                    0.9,
                ));
            }

            // Insecure network: socket without TLS
            if trimmed.contains("socket.connect(") || trimmed.contains("socket.tcp(") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Medium,
                    "CWE-319",
                    "Cleartext Network Communication",
                    "Plain TCP socket connection. Use TLS (socket.tls() or https) for sensitive data transmission.",
                    0.8,
                ));
            }

            // Weak / custom crypto
            if (trimmed.contains("string.char(") || trimmed.contains("bit.bxor("))
                && trimmed.matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != '(' && c != ')' && c != ',' && c != ' ').count() >= 3
            {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Medium,
                    "CWE-327",
                    "Custom Cryptography",
                    "Manual bitwise / char-based crypto operations. Use established cryptographic libraries instead of rolling your own.",
                    0.75,
                ));
            }

            // Insecure random: math.random used for security
            if trimmed.contains("math.random(") || trimmed.contains("math.randomseed(") {
                findings.push(make_finding(
                    file_path, lineno, trimmed,
                    Severity::Low,
                    "CWE-338",
                    "Weak Random Number Generator",
                    "math.random() is not cryptographically secure. Use a CSPRNG for security-sensitive operations.",
                    0.7,
                ));
            }
        }

        findings
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    file_path: &Path,
    line_number: u32,
    snippet: &str,
    severity: Severity,
    cwe: &str,
    title: &str,
    remediation: &str,
    confidence: f32,
) -> Finding {
    Finding {
        id: crate::new_finding_id(),
        severity,
        cwe: Some(cwe.to_string()),
        cve: None,
        description: format!("{} — {}", title, cwe),
        file_path: Some(file_path.to_path_buf()),
        line_number: Some(line_number),
        vulnerable_code_snippet: Some(snippet.trim().to_string()),
        remediation: Some(remediation.to_string()),
        confidence,
        discovery_method: DiscoveryMethod::StaticPatternMatching,
        ..Default::default()
    }
}

fn has_quoted_literal_path(s: &str) -> bool {
    if s.contains('\'') { {
        let mut in_string = false;
        let mut has_concat = false;
        for (j, c) in s.char_indices() {
            if c == '\'' || c == '"' {
                in_string = !in_string;
            }
            if !in_string && s[j..].starts_with("..") {
                has_concat = true;
            }
        }
        !has_concat
    } } else { false }
}

fn is_secret_assignment(s: &str) -> bool {
    let secrets = [
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "api_secret", "apisecret", "access_key", "accesskey",
        "auth_token", "authtoken", "token", "private_key",
    ];
    let lower = s.to_lowercase();
    secrets.iter().any(|kw| {
        if let Some(pos) = lower.find(kw) {
            let before = pos.checked_sub(1).map(|p| s.as_bytes()[p] as char).unwrap_or(' ');
            let after = pos + kw.len();
            let after_char = s.as_bytes().get(after).copied().map(char::from).unwrap_or(' ');
            !before.is_alphanumeric() && (after_char == ' ' || after_char == '=' || after_char == '\t')
                && s[after..].contains('=')
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::LanguageAnalyzer;

    #[test]
    fn test_lua_command_injection() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "local result = os.execute(\"rm -rf /\")\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect os.execute");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-78"));
    }

    #[test]
    fn test_lua_code_injection() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "loadstring(user_input)()\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect loadstring");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-94"));
    }

    #[test]
    fn test_lua_sql_injection() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "db:execute(\"SELECT * FROM users WHERE id = \" .. id)\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect SQL injection");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn test_lua_path_traversal() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "local f = io.open(\"/var/data/\" .. filename, \"r\")\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect path traversal");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-22"));
    }

    #[test]
    fn test_lua_hardcoded_secret() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "local password = \"supersecret123\"\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect hardcoded secret");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-798"));
    }

    #[test]
    fn test_lua_insecure_network() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "local sock = socket.connect(\"example.com\", 80)\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect insecure network");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-319"));
    }

    #[test]
    fn test_lua_weak_random() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "math.randomseed(os.time())\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect weak random");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-338"));
    }

    #[test]
    fn test_lua_clean_code_no_findings() {
        let analyzer = LuaAnalyzer::default();
        let code = r#"-- hello.lua
local function greet(name)
    print("Hello, " .. name)
end

local function add(a, b)
    return a + b
end

greet("world")
print(add(1, 2))
"#;
        let findings = analyzer.analyze(code, Path::new("test.lua"), &ScanConfig::default());
        assert!(findings.is_empty(), "clean code should have no findings");
    }

    #[test]
    fn test_lua_multiple_vulnerabilities() {
        let analyzer = LuaAnalyzer::default();
        let code = "os.execute(\"ls\")\nloadstring(code)\nlocal p = \"secret123\"\n";
        let findings = analyzer.analyze(code, Path::new("test.lua"), &ScanConfig::default());
        assert!(findings.len() >= 2, "should detect multiple issues");
    }

    #[test]
    fn test_lua_dofile_inclusion() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "dofile(\"/etc/passwd\")\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect dofile");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-829"));
    }

    #[test]
    fn test_lua_io_popen_injection() {
        let analyzer = LuaAnalyzer::default();
        let findings = analyzer.analyze(
            "local f = io.popen(\"ls -la \" .. dir)\n",
            Path::new("test.lua"),
            &ScanConfig::default(),
        );
        assert!(!findings.is_empty(), "should detect io.popen");
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-78"));
    }
}
