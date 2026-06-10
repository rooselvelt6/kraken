pub struct ClippyAnalyzer;

impl Default for ClippyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClippyAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn run(&self, path: &std::path::Path) -> Vec<crate::Finding> {
        let mut findings = Vec::new();

        let output = std::process::Command::new("cargo")
            .args(["clippy", "--message-format=json"])
            .current_dir(path)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                    if json.get("message").is_some() {
                        let msg = &json["message"];
                        let level = msg["level"].as_str().unwrap_or("");
                        if level == "warning" || level == "error" {
                            let severity = match level {
                                "error" => crate::Severity::High,
                                _ => crate::Severity::Medium,
                            };

                            findings.push(crate::Finding {
                                id: crate::new_finding_id(),
                                severity,
                                cwe: None,
                                cve: None,
                                description: msg["message"]
                                    .as_str()
                                    .unwrap_or("Clippy warning")
                                    .to_string(),
                                file_path: msg["spans"]
                                    .get(0)
                                    .and_then(|s| s["file_name"].as_str())
                                    .map(std::path::PathBuf::from),
                                line_number: msg["spans"]
                                    .get(0)
                                    .and_then(|s| s["line_start"].as_u64())
                                    .map(|l| l as u32),
                                vulnerable_code_snippet: None,
                                remediation: Some("Fix clippy warning".to_string()),
                                confidence: 0.9,
                                discovery_method: crate::DiscoveryMethod::StaticPatternMatching,
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
