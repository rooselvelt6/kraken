use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCve {
    pub id: String,
    pub source_identifier: String,
    pub published: String,
    pub last_modified: String,
    pub descriptions: Vec<LangString>,
    pub metrics: Option<NvdMetrics>,
    pub weaknesses: Vec<NvdWeakness>,
    pub references: Vec<NvdReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LangString {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdMetrics {
    pub cvss_v3: Option<CvssV3>,
    pub cvss_v2: Option<CvssV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssV3 {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality: String,
    pub integrity: String,
    pub availability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssV2 {
    pub version: String,
    pub base_score: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdWeakness {
    pub c_type: String,
    pub description: Vec<LangString>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdReference {
    pub url: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdSearchResult {
    pub total_results: u32,
    pub results_per_page: u32,
    pub vulnerabilities: Vec<NvdCve>,
    pub query: String,
}

pub struct NvdClient;

impl NvdClient {
    pub fn new() -> Self {
        NvdClient
    }

    pub fn search_cve(keyword: &str) -> NvdSearchResult {
        let vulns = Self::search_local(keyword);
        NvdSearchResult {
            total_results: vulns.len() as u32,
            results_per_page: 20,
            vulnerabilities: vulns,
            query: keyword.to_string(),
        }
    }

    pub fn search_by_cve_id(cve_id: &str) -> Option<NvdCve> {
        let all = Self::search_local("");
        all.into_iter().find(|c| c.id == cve_id)
    }

    fn search_local(keyword: &str) -> Vec<NvdCve> {
        let kw = keyword.to_lowercase();
        let db = Self::sample_db();
        db.into_iter().filter(|cve| {
            cve.id.to_lowercase().contains(&kw)
                || cve.descriptions.iter().any(|d| d.value.to_lowercase().contains(&kw))
        }).collect()
    }

    fn sample_db() -> Vec<NvdCve> {
        vec![
            NvdCve {
                id: "CVE-2024-0001".to_string(),
                source_identifier: "nvd@nist.gov".to_string(),
                published: "2024-01-01T00:00:00Z".to_string(),
                last_modified: "2024-06-01T00:00:00Z".to_string(),
                descriptions: vec![
                    LangString { lang: "en".to_string(), value: "Buffer overflow in OpenSSL 1.0.x".to_string() },
                ],
                metrics: Some(NvdMetrics {
                    cvss_v3: Some(CvssV3 {
                        version: "3.1".to_string(),
                        vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                        base_score: 9.8,
                        base_severity: "CRITICAL".to_string(),
                        attack_vector: "Network".to_string(),
                        attack_complexity: "Low".to_string(),
                        privileges_required: "None".to_string(),
                        user_interaction: "None".to_string(),
                        scope: "Unchanged".to_string(),
                        confidentiality: "High".to_string(),
                        integrity: "High".to_string(),
                        availability: "High".to_string(),
                    }),
                    cvss_v2: None,
                }),
                weaknesses: vec![],
                references: vec![NvdReference {
                    url: "https://nvd.nist.gov".to_string(),
                    tags: vec!["Patch".to_string()],
                }],
            },
            NvdCve {
                id: "CVE-2024-0002".to_string(),
                source_identifier: "nvd@nist.gov".to_string(),
                published: "2024-02-15T00:00:00Z".to_string(),
                last_modified: "2024-05-01T00:00:00Z".to_string(),
                descriptions: vec![
                    LangString { lang: "en".to_string(), value: "Remote code execution in libcurl".to_string() },
                ],
                metrics: Some(NvdMetrics {
                    cvss_v3: Some(CvssV3 {
                        version: "3.1".to_string(),
                        vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H".to_string(),
                        base_score: 8.8,
                        base_severity: "HIGH".to_string(),
                        attack_vector: "Network".to_string(),
                        attack_complexity: "Low".to_string(),
                        privileges_required: "None".to_string(),
                        user_interaction: "Required".to_string(),
                        scope: "Unchanged".to_string(),
                        confidentiality: "High".to_string(),
                        integrity: "High".to_string(),
                        availability: "High".to_string(),
                    }),
                    cvss_v2: None,
                }),
                weaknesses: vec![],
                references: vec![],
            },
        ]
    }

    pub fn severity_color(severity: &str) -> &'static str {
        match severity {
            "CRITICAL" => "\x1b[31m",
            "HIGH" => "\x1b[33m",
            "MEDIUM" => "\x1b[33m",
            "LOW" => "\x1b[32m",
            _ => "\x1b[0m",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_by_cve() {
        let result = NvdClient::search_cve("openssl");
        assert!(result.total_results > 0);
    }

    #[test]
    fn test_search_by_cve_id() {
        let cve = NvdClient::search_by_cve_id("CVE-2024-0001");
        assert!(cve.is_some());
    }

    #[test]
    fn test_search_nonexistent() {
        let result = NvdClient::search_cve("nonexistent-vuln-xyz");
        assert_eq!(result.total_results, 0);
    }

    #[test]
    fn test_cvss_fields() {
        let cve = NvdClient::search_by_cve_id("CVE-2024-0001").unwrap();
        let cvss = cve.metrics.unwrap().cvss_v3.unwrap();
        assert_eq!(cvss.base_score, 9.8);
    }

    #[test]
    fn test_nvd_result_serde() {
        let result = NvdClient::search_cve("test");
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("total_results"));
    }
}
