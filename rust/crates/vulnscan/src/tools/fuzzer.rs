pub struct CargoFuzzer;

impl Default for CargoFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoFuzzer {
    pub fn new() -> Self { Self }

    pub fn run(&self, path: &std::path::Path) -> Vec<crate::Finding> {
        let mut findings = Vec::new();

        // Check if fuzz target exists
        if !path.join("fuzz").exists() {
            return findings;
        }

        let output = std::process::Command::new("cargo")
            .args(["fuzz", "run"])
            .current_dir(path.join("fuzz"))
            .output();

        if let Ok(output) = output {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("panic")
                    || stderr.contains("crash")
                    || stderr.contains("timeout")
                {
                    findings.push(crate::Finding {
                        id: crate::new_finding_id(),
                        severity: crate::Severity::Critical,
                        cwe: Some("CWE-20".to_string()),
                        cve: None,
                        description: "Fuzzing discovered potential crash".to_string(),
                        file_path: Some(path.join("fuzz")),
                        line_number: None,
                        vulnerable_code_snippet: None,
                        remediation: Some("Review fuzzing output and fix crashes".to_string()),
                        confidence: 0.8,
                        discovery_method: crate::DiscoveryMethod::Fuzzing,
                    });
                }
            }
        }

        findings
    }
}
