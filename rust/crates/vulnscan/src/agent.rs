use crate::{ExploitType, Finding, FindingStatus, Language, ScanConfig, Severity};
use api::{InputMessage, MessageRequest, ProviderClient};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const KRAKEN_SYSTEM_PROMPT: &str = "You are Kraken, an advanced vulnerability research agent.
Your methodology:
1. IDENTIFY — Find subtle bugs humans miss (logic flaws, race conditions, type confusion, integer overflows)
2. EXPLOIT — Generate working PoC code for confirmed vulnerabilities
3. CHAIN — Combine multiple low-severity issues into critical exploit chains
4. VALIDATE — Assess exploitability with CVSS 3.1 scoring
5. REPORT — Produce clear, actionable findings

Think step by step. Be precise. Never fabricate vulnerabilities.";

pub struct SecurityAgent {
    provider: ProviderClient,
    model: String,
    max_tokens: u32,
    overnight_mode: bool,
}

impl SecurityAgent {
    pub fn new(model: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = ProviderClient::from_model(model)?;
        Ok(Self {
            provider,
            model: model.to_string(),
            max_tokens: 4096,
            overnight_mode: false,
        })
    }

    pub fn with_overnight(mut self) -> Self {
        self.overnight_mode = true;
        self.max_tokens = 8192;
        self
    }

    pub async fn analyze_file(&self, file_path: &Path, language: Language) -> Vec<Finding> {
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        if content.len() > 50_000 {
            return self
                .analyze_file_chunked(file_path, &content, language)
                .await;
        }
        let prompt = self.build_kraken_prompt(&content, language);
        match self.call_llm(&prompt).await {
            Ok(response) => self.parse_llm_findings(&response, file_path),
            Err(e) => {
                eprintln!("[agent] LLM call failed: {e}");
                vec![]
            }
        }
    }

    async fn analyze_file_chunked(
        &self,
        file_path: &Path,
        content: &str,
        _language: Language,
    ) -> Vec<Finding> {
        let mut all = vec![];
        for (i, chunk) in content.as_bytes().chunks(40_000).enumerate() {
            let chunk_str = String::from_utf8_lossy(chunk);
            let prompt = format!(
                "{}\n\n[Chunk {}/{} of {}]\n```\n{}\n```",
                KRAKEN_SYSTEM_PROMPT,
                i + 1,
                (content.len() + 39_999) / 40_000,
                file_path.display(),
                chunk_str
            );
            if let Ok(response) = self.call_llm(&prompt).await {
                all.extend(self.parse_llm_findings(&response, file_path));
            }
        }
        all
    }

    pub async fn rank_files(&self, files: &[PathBuf], config: &ScanConfig) -> Vec<(PathBuf, f32)> {
        let mut scores = Vec::with_capacity(files.len());
        for file in files {
            let score = self.estimate_bug_probability(file).await;
            scores.push((file.clone(), score));
        }
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        if let Some(max) = config.max_findings_per_path {
            scores.truncate(max);
        }
        scores
    }

    async fn estimate_bug_probability(&self, file_path: &Path) -> f32 {
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) if c.len() < 20_000 => c,
            _ => return 0.3,
        };
        let prompt = format!(
            "Rate the likelihood (0.0-1.0) that this file contains security vulnerabilities.
Respond with ONLY a number between 0 and 1.

File: {}
```{}
```",
            file_path.display(),
            &content[..content.len().min(8000)]
        );
        match self.call_llm(&prompt).await {
            Ok(r) => r.trim().parse::<f32>().unwrap_or(0.3).clamp(0.0, 1.0),
            Err(_) => 0.3,
        }
    }

    pub async fn validate_finding(&self, finding: &Finding) -> Finding {
        let prompt = format!(
            "Validate this security finding and respond with ONLY a JSON object:
{{
  \"valid\": true/false,
  \"cvss_score\": 0.0-10.0,
  \"adjusted_severity\": \"Critical\"/\"High\"/\"Medium\"/\"Low\"/\"Info\",
  \"notes\": \"\"
}}

Description: {}
CWE: {:?}
Severity: {:?}",
            finding.description, finding.cwe, finding.severity
        );
        match self.call_llm(&prompt).await {
            Ok(response) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&response) {
                    let valid = val.get("valid").and_then(|v| v.as_bool()).unwrap_or(true);
                    if !valid {
                        let mut f = finding.clone();
                        f.status = FindingStatus::FalsePositive;
                        return f;
                    }
                    let mut f = finding.clone();
                    f.cvss_score = val
                        .get("cvss_score")
                        .and_then(|v| v.as_f64().map(|s| s as f32));
                    if let Some(sev_str) = val.get("adjusted_severity").and_then(|v| v.as_str()) {
                        f.severity = Severity::from_str(sev_str);
                    }
                    f.severity_confidence = 0.9;
                    return f;
                }
                finding.clone()
            }
            Err(_) => finding.clone(),
        }
    }

    pub async fn generate_exploit(&self, finding: &Finding) -> Finding {
        let prompt = format!(
            "Generate a working PoC exploit for this vulnerability.
Respond with JSON: {{\"language\":\"python\",\"code\":\"...\",\"type\":\"RCE|PrivEsc|DoS|AuthBypass\",\"notes\":\"\"}}

Description: {}
CWE: {:?}
Severity: {:?}
File: {:?}",
            finding.description, finding.cwe, finding.severity, finding.file_path
        );
        match self.call_llm(&prompt).await {
            Ok(response) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&response) {
                    let code = val
                        .get("code")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let etype = val
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown");
                    let exploit_type = match etype {
                        "RCE" => ExploitType::RemoteCodeExecution,
                        "PrivEsc" => ExploitType::PrivilegeEscalation,
                        "DoS" => ExploitType::DenialOfService,
                        "AuthBypass" => ExploitType::AuthenticationBypass,
                        _ => ExploitType::Unknown,
                    };
                    return crate::exploit::create_exploit_finding(finding, code, exploit_type);
                }
                finding.clone()
            }
            Err(_) => finding.clone(),
        }
    }

    pub async fn overnight_scan(&self, config: &ScanConfig) -> Vec<Finding> {
        let files = self.collect_target_files(config);
        let ranked = self.rank_files(&files, config).await;
        let mut all_findings = vec![];

        for (file, _score) in &ranked {
            let lang = crate::analyzers::detect_language(file, None);
            if !config.languages.contains(&lang) && lang != Language::Other {
                continue;
            }
            let findings = self.analyze_file(file, lang).await;
            all_findings.extend(findings);

            if let Some(max) = config.max_findings_per_path {
                if all_findings.len() >= max {
                    break;
                }
            }
        }

        for finding in &mut all_findings {
            if config.enable_exploit_generation {
                let exploit_finding = self
                    .generate_exploit(&Finding {
                        description: finding.description.clone(),
                        severity: finding.severity,
                        cwe: finding.cwe.clone(),
                        file_path: finding.file_path.clone(),
                        line_number: finding.line_number,
                        ..Default::default()
                    })
                    .await;
                finding.exploit_code = exploit_finding.exploit_code;
                finding.exploit_type = exploit_finding.exploit_type;
            }
        }

        all_findings
    }

    fn collect_target_files(&self, config: &ScanConfig) -> Vec<PathBuf> {
        let mut files = vec![];
        let ext_map: HashMap<&str, Language> = {
            let mut m = HashMap::new();
            for lang in &config.languages {
                for ext in lang.extensions() {
                    m.insert(*ext, *lang);
                }
            }
            m
        };
        for target in &config.target_paths {
            if !target.exists() {
                continue;
            }
            if target.is_file() {
                files.push(target.clone());
            } else {
                for entry in WalkDir::new(target)
                    .follow_links(true)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if ext_map.contains_key(ext) || ext_map.is_empty() {
                                files.push(path.to_path_buf());
                            }
                        }
                    }
                }
            }
        }
        files
    }

    fn build_kraken_prompt(&self, content: &str, language: Language) -> String {
        format!(
            "{}

## Target
Language: {lang:?}
Code size: {size} bytes

## Code
```{lang_lower}
{content}
```

## Instructions
Analyze the code above for security vulnerabilities using the Kraken methodology.
For each finding, respond with a JSON array:
[
  {{
    \"severity\": \"Critical\" | \"High\" | \"Medium\" | \"Low\" | \"Info\",
    \"cwe\": \"CWE-XXX\",
    \"description\": \"What and where\",
    \"line\": 42,
    \"snippet\": \"vulnerable line or context\",
    \"remediation\": \"How to fix\",
    \"confidence\": 0.0-1.0
  }}
]

Focus on: memory safety, injection, auth bypass, crypto flaws, race conditions, logic errors.",
            KRAKEN_SYSTEM_PROMPT,
            lang = language,
            size = content.len(),
            lang_lower = format!("{:?}", language).to_lowercase(),
            content = content
        )
    }

    async fn call_llm(
        &self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let request = MessageRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            messages: vec![InputMessage::user_text(prompt)],
            system: Some(KRAKEN_SYSTEM_PROMPT.to_string()),
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

    fn parse_llm_findings(&self, response: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = vec![];

        let json_str = extract_json_array(response).unwrap_or(response);
        if let Ok(array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
            for item in array {
                let severity = Severity::from_str(
                    item.get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Info"),
                );
                let confidence = item
                    .get("confidence")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5) as f32;

                findings.push(Finding {
                    id: crate::new_finding_id(),
                    severity,
                    cwe: item
                        .get("cwe")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    cve: None,
                    description: item
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("No description")
                        .to_string(),
                    file_path: Some(file_path.to_path_buf()),
                    line_number: item.get("line").and_then(|v| v.as_u64().map(|l| l as u32)),
                    vulnerable_code_snippet: item
                        .get("snippet")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    remediation: item
                        .get("remediation")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    confidence,
                    discovery_method: crate::DiscoveryMethod::LLMAgent,
                    exploit_code: None,
                    exploit_type: None,
                    chained_findings: vec![],
                    poc_validated: false,
                    status: FindingStatus::Open,
                    cvss_score: None,
                    severity_confidence: confidence,
                    discovered_at: chrono::Utc::now(),
                    disclosed: false,
                    disclosure_hash: None,
                });
            }
        }
        findings
    }
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
