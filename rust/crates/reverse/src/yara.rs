use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub meta: HashMap<String, String>,
    pub tags: Vec<String>,
    pub matches: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub matched_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub file: String,
    pub matches: Vec<YaraMatch>,
    pub rules_used: Vec<String>,
    pub scan_time_ms: u64,
}

pub struct YaraScanner;

impl YaraScanner {
    pub fn scan_file(file_path: &str, rules_file: &str) -> Result<YaraScanResult, String> {
        let start = std::time::Instant::now();

        let output = Command::new("yara")
            .args([
                "-s",
                rules_file,
                file_path,
            ])
            .output()
            .map_err(|e| format!("yara command failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && !stderr.is_empty() {
            return Err(format!("yara error: {}", stderr.trim()));
        }

        let matches = Self::parse_output(&stdout);
        let elapsed = start.elapsed().as_millis() as u64;

        Ok(YaraScanResult {
            file: file_path.to_string(),
            matches,
            rules_used: vec![rules_file.to_string()],
            scan_time_ms: elapsed,
        })
    }

    pub fn scan_with_rules(file_path: &str, rules: &[&str]) -> Result<YaraScanResult, String> {
        let tmp_file = format!("/tmp/kraken_yara_rules_{}.yar", std::process::id());
        let rule_content = rules.join("\n\n");
        std::fs::write(&tmp_file, &rule_content)
            .map_err(|e| format!("Cannot write rules: {}", e))?;

        let result = Self::scan_file(file_path, &tmp_file);
        let _ = std::fs::remove_file(&tmp_file);
        result
    }

    pub fn list_rules(rules_file: &str) -> Result<Vec<String>, String> {
        let output = Command::new("yara")
            .args(["-L", rules_file])
            .output()
            .map_err(|e| format!("yara -L failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().map(|l| l.trim().to_string()).collect())
    }

    fn parse_output(output: &str) -> Vec<YaraMatch> {
        let mut matches = Vec::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }

            if !trimmed.starts_with("0x") && !trimmed.contains(" at ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let rule_name = parts[0].to_string();
                    let matched_file = parts[1].to_string();

                    let mut yara_match = YaraMatch {
                        rule: rule_name,
                        namespace: "default".to_string(),
                        meta: HashMap::new(),
                        tags: Vec::new(),
                        matches: Vec::new(),
                    };

                    if let Some(existing) = matches.iter_mut().rev().find(|m: &&mut YaraMatch| m.rule == yara_match.rule) {
                        if let Some(string_match) = Self::parse_string_match(line) {
                            existing.matches.push(string_match);
                        }
                    } else {
                        if !matches.iter().any(|m| m.rule == yara_match.rule && m.file_in_match().as_deref() == Some(&matched_file)) {
                            if let Some(string_match) = Self::parse_string_match(line) {
                                yara_match.matches.push(string_match);
                            }
                            matches.push(yara_match);
                        }
                    }
                }
            }
        }

        matches
    }

    fn parse_string_match(line: &str) -> Option<YaraStringMatch> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 { return None; }

        let identifier = parts.first()?.to_string();
        let offset_str = parts.get(1)?.trim_end_matches(':');

        let offset = if let Some(hex) = offset_str.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            offset_str.parse::<u64>().ok()
        }?;

        let matched_data = if parts.len() > 2 {
            parts[2..].join(" ")
        } else {
            String::new()
        };

        Some(YaraStringMatch {
            identifier,
            offset,
            matched_data,
        })
    }

    pub fn compile_rule(rule_text: &str) -> Result<String, String> {
        let tmp_yar = format!("/tmp/kraken_yarac_{}.yar", std::process::id());
        let tmp_compiled = format!("/tmp/kraken_yarac_{}.yc", std::process::id());

        std::fs::write(&tmp_yar, rule_text)
            .map_err(|e| format!("Cannot write rule: {}", e))?;

        let output = Command::new("yarac")
            .args([&tmp_yar, &tmp_compiled])
            .output()
            .map_err(|e| format!("yarac failed: {}", e))?;

        let _ = std::fs::remove_file(&tmp_yar);

        if output.status.success() {
            let compiled = std::fs::read(&tmp_compiled)
                .map_err(|e| format!("Cannot read compiled: {}", e))?;
            let _ = std::fs::remove_file(&tmp_compiled);
            Ok(hex::encode(&compiled))
        } else {
            let _ = std::fs::remove_file(&tmp_compiled);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("yarac error: {}", stderr.trim()))
        }
    }
}

impl YaraMatch {
    pub fn file_in_match(&self) -> Option<String> {
        None
    }
}

pub fn format_yara_result(result: &YaraScanResult) -> String {
    if result.matches.is_empty() {
        return format!("No YARA matches in {}\n", result.file);
    }

    let mut out = format!("YARA Scan Results for {}\n", result.file);
    out.push_str(&format!("Rules: {}\n", result.rules_used.join(", ")));
    out.push_str(&format!("Time: {}ms\n", result.scan_time_ms));
    out.push_str(&format!("Matches: {}\n\n", result.matches.len()));

    for (i, m) in result.matches.iter().enumerate() {
        out.push_str(&format!("{}. Rule: {} ({})\n", i + 1, m.rule, m.namespace));
        if !m.tags.is_empty() {
            out.push_str(&format!("   Tags: {}\n", m.tags.join(", ")));
        }
        for sm in &m.matches {
            out.push_str(&format!("   {} at {:#x}: {}\n", sm.identifier, sm.offset, sm.matched_data));
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_match_struct() {
        let mut meta = HashMap::new();
        meta.insert("description".to_string(), "Test rule".to_string());
        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "default".to_string(),
            meta,
            tags: vec!["test".to_string()],
            matches: vec![YaraStringMatch {
                identifier: "$a".to_string(),
                offset: 0x100,
                matched_data: "test data".to_string(),
            }],
        };
        assert_eq!(yara_match.rule, "test_rule");
        assert_eq!(yara_match.matches.len(), 1);
        assert_eq!(yara_match.matches[0].offset, 0x100);
    }

    #[test]
    fn test_yara_scan_result_format_empty() {
        let result = YaraScanResult {
            file: "/tmp/test.bin".to_string(),
            matches: vec![],
            rules_used: vec!["test.yar".to_string()],
            scan_time_ms: 10,
        };
        let formatted = format_yara_result(&result);
        assert!(formatted.contains("No YARA matches"));
    }

    #[test]
    fn test_yara_scan_result_format_with_matches() {
        let result = YaraScanResult {
            file: "/tmp/test.bin".to_string(),
            matches: vec![YaraMatch {
                rule: "malware".to_string(),
                namespace: "default".to_string(),
                meta: HashMap::new(),
                tags: vec!["malicious".to_string()],
                matches: vec![],
            }],
            rules_used: vec!["rules.yar".to_string()],
            scan_time_ms: 50,
        };
        let formatted = format_yara_result(&result);
        assert!(formatted.contains("malware"));
        assert!(formatted.contains("malicious"));
    }

    #[test]
    fn test_parse_yara_output_line() {
        let line = "$a_string 0x1234: This is the matched data";
        let parsed = YaraScanner::parse_string_match(line);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.identifier, "$a_string");
        assert_eq!(parsed.offset, 0x1234);
    }

    #[test]
    fn test_list_rules_nonexistent() {
        let result = YaraScanner::list_rules("/tmp/nonexistent.yar");
        assert!(result.is_err());
    }
}
