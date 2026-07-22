use crate::{Finding, FindingStatus};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct DisclosurePipeline {
    disclosures_dir: PathBuf,
}

impl DisclosurePipeline {
    pub fn new(base_dir: &Path) -> Self {
        let dir = base_dir.join("disclosures");
        if let Err(e) = fs::create_dir_all(&dir) {
            eprintln!(
                "[disclosure] Failed to create disclosures dir {}: {e}",
                dir.display()
            );
        }
        Self {
            disclosures_dir: dir,
        }
    }

    /// Computes a SHA-3 commitment hash for a finding.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::{Finding, Severity, DiscoveryMethod};
    /// use vulnscan::disclosure::DisclosurePipeline;
    /// let f = Finding::new(Severity::High, "test vuln", None, None, None, None, Some("CWE-120".to_string()), 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let hash = DisclosurePipeline::commit_hash(&f);
    /// assert_eq!(hash.len(), 64); // SHA-3 256 hex
    /// ```
    pub fn commit_hash(finding: &Finding) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(finding.id.as_bytes());
        hasher.update(finding.description.as_bytes());
        hasher.update(format!("{:?}", finding.severity).as_bytes());
        hasher.update(finding.cwe.as_deref().unwrap_or("none").as_bytes());
        if let Some(path) = &finding.file_path {
            hasher.update(path.to_string_lossy().as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn generate_report(&self, finding: &Finding) -> String {
        format!(
            "# Vulnerability Report\n\
             \nID: {}\n\
             Severity: {:?}\n\
             CWE: {}\n\
             CVE: {}\n\
             Description: {}\n\
             File: {}\n\
             Line: {}\n\
             SHA-3 Commitment: {}\n\
             \n## Remediation\n{}\n\
             \n## Proof of Concept\n{}\n",
            finding.id,
            finding.severity,
            finding.cwe.as_deref().unwrap_or("N/A"),
            finding.cve.as_deref().unwrap_or("N/A"),
            finding.description,
            finding
                .file_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            finding
                .line_number
                .map(|l| l.to_string())
                .unwrap_or_default(),
            Self::commit_hash(finding),
            finding.remediation.as_deref().unwrap_or("N/A"),
            finding.exploit_code.as_deref().unwrap_or("N/A"),
        )
    }

    pub fn save_report(&self, finding: &Finding) -> Result<PathBuf, String> {
        let report = self.generate_report(finding);
        let report_path = self.disclosures_dir.join(format!("{}.md", finding.id));
        fs::write(&report_path, &report)
            .map_err(|e| format!("Failed to write disclosure report: {}", e))?;
        Ok(report_path)
    }

    /// Computes a CVSS-like score for a finding based on severity and confidence.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::{Finding, Severity, DiscoveryMethod};
    /// use vulnscan::disclosure::DisclosurePipeline;
    /// let f = Finding::new(Severity::Critical, "test", None, None, None, None, None, 0.9, DiscoveryMethod::StaticPatternMatching);
    /// let score = DisclosurePipeline::compute_cvss(&f);
    /// assert!(score >= 9.0 && score <= 10.0);
    /// ```
    pub fn compute_cvss(finding: &Finding) -> f32 {
        let base = match finding.severity {
            crate::Severity::Critical => 9.0,
            crate::Severity::High => 7.5,
            crate::Severity::Medium => 5.0,
            crate::Severity::Low => 2.5,
            crate::Severity::Info => 0.0,
        };
        let exploitability_bonus = if finding.exploit_code.is_some() {
            1.0
        } else {
            0.0
        };
        let confidence_bonus = finding.confidence * 0.5;
        (base + exploitability_bonus + confidence_bonus).min(10.0)
    }

    pub fn update_status(&self, finding_id: &str, status: FindingStatus) -> Result<(), String> {
        let report_path = self.disclosures_dir.join(format!("{}.md", finding_id));
        if !report_path.exists() {
            return Err(format!("Report not found: {}", finding_id));
        }
        let content = fs::read_to_string(&report_path)
            .map_err(|e| format!("Failed to read report: {}", e))?;
        let updated = if status == FindingStatus::Patched || status == FindingStatus::Fixed {
            let hash = Self::compute_hash(&content);
            format!(
                "{}\n\n## Disclosure\nStatus: {:?}\nHash: {}\nDisclosed: {}",
                content,
                status,
                hash,
                chrono::Utc::now().to_rfc3339()
            )
        } else {
            format!("{}\n\nStatus: {:?}", content, status)
        };
        fs::write(&report_path, &updated).map_err(|e| format!("Failed to update report: {}", e))?;
        Ok(())
    }

    fn compute_hash(content: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
