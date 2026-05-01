use crate::{Finding, Language};
use std::path::Path;

pub struct VulnerabilityAgent {
    ollama_url: String,
    model: String,
}

impl VulnerabilityAgent {
    pub fn new() -> Self {
        Self {
            ollama_url: "http://localhost:11434".to_string(),
            model: "llama3.2".to_string(),
        }
    }

    pub fn with_ollama(url: &str, model: &str) -> Self {
        Self {
            ollama_url: url.to_string(),
            model: model.to_string(),
        }
    }

    pub async fn analyze_file(&self, file_path: &Path, language: Language) -> Vec<Finding> {
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let prompt = self.build_mythos_prompt(&content, language);

        match self.call_ollama(&prompt).await {
            Ok(response) => self.parse_llm_response(&response, file_path),
            Err(_) => vec![],
        }
    }

    fn build_mythos_prompt(&self, content: &str, language: Language) -> String {
        format!(
            "You are a vulnerability analyst using Mythos methodology.\n\
             Analyze this {:?} code for security vulnerabilities.\n\n\
             Code:\n```\n{}\n```\n\n\
             Respond in JSON format with an array of findings:\n\
             [{{\"severity\": \"High\", \"cwe\": \"CWE-XXX\", \"description\": \"...\", \"line\": 1, \"remediation\": \"...\"}}]",
            language, content
        )
    }

    async fn call_ollama(&self, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });

        let response = client
            .post(format!("{}/api/generate", self.ollama_url))
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["response"].as_str().unwrap_or("").to_string())
    }

    fn parse_llm_response(&self, response: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
            if let Some(array) = json.as_array() {
                for item in array {
                    let severity = match item["severity"].as_str() {
                        Some("Critical") => crate::Severity::Critical,
                        Some("High") => crate::Severity::High,
                        Some("Medium") => crate::Severity::Medium,
                        Some("Low") => crate::Severity::Low,
                        _ => crate::Severity::Info,
                    };

                    findings.push(Finding {
                        id: crate::new_finding_id(),
                        severity,
                        cwe: item["cwe"].as_str().map(|s| s.to_string()),
                        cve: None,
                        description: item["description"].as_str().unwrap_or("").to_string(),
                        file_path: Some(file_path.to_path_buf()),
                        line_number: item["line"].as_u64().map(|l| l as u32),
                        vulnerable_code_snippet: item["snippet"].as_str().map(|s| s.to_string()),
                        remediation: item["remediation"].as_str().map(|s| s.to_string()),
                        confidence: 0.8,
                        discovery_method: crate::DiscoveryMethod::LLMAgent,
                    });
                }
            }
        }

        findings
    }
}

impl Default for VulnerabilityAgent {
    fn default() -> Self {
        Self::new()
    }
}
