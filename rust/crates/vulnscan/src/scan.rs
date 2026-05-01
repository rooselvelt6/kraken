use crate::{
    analyzers::{self, LanguageAnalyzer},
    Finding, Language, ScanConfig,
};
use std::path::Path;
use walkdir::WalkDir;

pub struct VulnerabilityScanner {
    config: ScanConfig,
}

impl VulnerabilityScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub fn scan(&self) -> Vec<Finding> {
        let mut all_findings = Vec::new();
        let analyzers = analyzers::load_all_analyzers();

        for target in &self.config.target_paths {
            if !target.exists() {
                continue;
            }

            if target.is_file() {
                self.scan_file(target, &analyzers, &mut all_findings);
            } else {
                self.scan_directory(target, &analyzers, &mut all_findings);
            }
        }

        self.filter_by_severity(all_findings)
    }

    fn scan_directory(
        &self,
        dir: &Path,
        analyzers: &[Box<dyn LanguageAnalyzer + Send + Sync>],
        findings: &mut Vec<Finding>,
    ) {
        for entry in WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                self.scan_file(path, analyzers, findings);
            }
        }
    }

    fn scan_file(
        &self,
        file_path: &Path,
        analyzers: &[Box<dyn LanguageAnalyzer + Send + Sync>],
        findings: &mut Vec<Finding>,
    ) {
        let language = analyzers::detect_language(file_path);

        if !self.config.languages.contains(&language) && language != Language::Other {
            return;
        }

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return,
        };

        for analyzer in analyzers {
            if analyzer.language() == language || language == Language::Other {
                let mut file_findings = analyzer.analyze(&content, file_path, &self.config);
                findings.append(&mut file_findings);

                if let Some(max) = self.config.max_findings_per_path {
                    if findings.len() >= max {
                        break;
                    }
                }
            }
        }
    }

    fn filter_by_severity(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| f.severity.value() >= self.config.min_severity.value())
            .collect()
    }
}
