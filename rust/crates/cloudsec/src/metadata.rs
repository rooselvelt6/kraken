use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataResponse {
    pub source: String,
    pub fields: HashMap<String, String>,
    pub raw: String,
    pub accessible: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataFinding {
    pub endpoint: String,
    pub accessible: bool,
    pub data: Option<String>,
    pub risk: String,
}

pub struct CloudMetadataApi;

impl Default for CloudMetadataApi {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudMetadataApi {
    pub fn new() -> Self {
        CloudMetadataApi
    }

    pub fn check_aws() -> Result<MetadataResponse, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build().map_err(|e| format!("client: {}", e))?;

        let imds_urls = vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ];

        let mut fields = HashMap::new();
        let mut raw = String::new();
        let mut accessible = false;

        for url in &imds_urls {
            match client.get(*url).send() {
                Ok(resp) if resp.status().is_success() => {
                    accessible = true;
                    if let Ok(body) = resp.text() {
                        raw.push_str(&format!("=== {} ===\n{}\n", url, body));
                        fields.insert(url.to_string(), body.chars().take(200).collect());
                    }
                }
                _ => {}
            }
        }

        if accessible {
            if let Ok(creds_resp) = client.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/").send() {
                if let Ok(roles) = creds_resp.text() {
                    for role in roles.lines() {
                        let role_url = format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{}", role);
                        if let Ok(role_resp) = client.get(&role_url).send() {
                            if let Ok(role_body) = role_resp.text() {
                                fields.insert(format!("iam_role:{}", role), role_body.chars().take(200).collect());
                            }
                        }
                    }
                }
            }
        }

        Ok(MetadataResponse {
            source: "AWS IMDS".to_string(),
            fields,
            raw,
            accessible,
        })
    }

    pub fn check_gcp() -> Result<MetadataResponse, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build().map_err(|e| format!("client: {}", e))?;

        let mut fields = HashMap::new();
        let mut raw = String::new();
        let mut accessible = false;

        let gcp_urls = vec![
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        ];

        for url in &gcp_urls {
            match client.get(*url).header("Metadata-Flavor", "Google").send() {
                Ok(resp) if resp.status().is_success() => {
                    accessible = true;
                    if let Ok(body) = resp.text() {
                        raw.push_str(&format!("=== {} ===\n{}\n", url, body));
                        fields.insert(url.to_string(), body.chars().take(200).collect());
                    }
                }
                _ => {}
            }
        }

        Ok(MetadataResponse {
            source: "GCP Metadata".to_string(),
            fields,
            raw,
            accessible,
        })
    }

    pub fn check_azure() -> Result<MetadataResponse, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build().map_err(|e| format!("client: {}", e))?;

        let mut fields = HashMap::new();
        let mut raw = String::new();
        let mut accessible = false;

        let azure_urls = vec![
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ];

        for url in &azure_urls {
            match client.get(*url).header("Metadata", "true").send() {
                Ok(resp) if resp.status().is_success() => {
                    accessible = true;
                    if let Ok(body) = resp.text() {
                        raw.push_str(&format!("=== {} ===\n{}\n", url, body));
                        fields.insert(url.to_string(), body.chars().take(200).collect());
                    }
                }
                _ => {}
            }
        }

        Ok(MetadataResponse {
            source: "Azure IMDS".to_string(),
            fields,
            raw,
            accessible,
        })
    }

    pub fn scan_all() -> Vec<MetadataFinding> {
        let mut findings = Vec::new();

        let aws = Self::check_aws().ok();
        if let Some(resp) = aws {
            findings.push(MetadataFinding {
                endpoint: "AWS IMDS".to_string(),
                accessible: resp.accessible,
                data: if resp.accessible { Some(resp.fields.keys().cloned().collect::<Vec<_>>().join(", ")) } else { None },
                risk: if resp.accessible { "CRITICAL: SSRF can access AWS instance metadata including IAM credentials".to_string() } else { "Not accessible".to_string() },
            });
        }

        let gcp = Self::check_gcp().ok();
        if let Some(resp) = gcp {
            findings.push(MetadataFinding {
                endpoint: "GCP Metadata".to_string(),
                accessible: resp.accessible,
                data: if resp.accessible { Some(resp.fields.keys().cloned().collect::<Vec<_>>().join(", ")) } else { None },
                risk: if resp.accessible { "CRITICAL: SSRF can access GCP service account tokens".to_string() } else { "Not accessible".to_string() },
            });
        }

        let azure = Self::check_azure().ok();
        if let Some(resp) = azure {
            findings.push(MetadataFinding {
                endpoint: "Azure IMDS".to_string(),
                accessible: resp.accessible,
                data: if resp.accessible { Some(resp.fields.keys().cloned().collect::<Vec<_>>().join(", ")) } else { None },
                risk: if resp.accessible { "CRITICAL: SSRF can access Azure Managed Identity tokens".to_string() } else { "Not accessible".to_string() },
            });
        }

        findings
    }

    pub fn check_ssrf_vulnerability(url: &str) -> Result<Vec<MetadataFinding>, String> {
        let mut findings = Vec::new();

        let metadata_ips = ["169.254.169.254", "169.254.170.2", "metadata.google.internal", "100.100.100.200"];

        for ip in &metadata_ips {
            let test_url = url.replace("TARGET", ip);
            if let Ok(client) = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                if let Ok(resp) = client.get(&test_url).send() {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 301 || status == 302 {
                        findings.push(MetadataFinding {
                            endpoint: ip.to_string(),
                            accessible: true,
                            data: Some(format!("HTTP {}", status)),
                            risk: format!("Potential SSRF: target resolved to cloud metadata IP {}", ip),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_aws() {
        let result = CloudMetadataApi::check_aws();
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.source, "AWS IMDS");
        // Most dev environments won't have IMDS accessible, that's fine
    }

    #[test]
    fn test_check_gcp() {
        let result = CloudMetadataApi::check_gcp();
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_azure() {
        let result = CloudMetadataApi::check_azure();
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_all() {
        let findings = CloudMetadataApi::scan_all();
        assert_eq!(findings.len(), 3); // aws, gcp, azure
    }

    #[test]
    fn test_check_ssrf() {
        let result = CloudMetadataApi::check_ssrf_vulnerability("http://TARGET/latest/meta-data/");
        assert!(result.is_ok());
    }

    #[test]
    fn test_metadata_finding() {
        let f = MetadataFinding {
            endpoint: "AWS".to_string(),
            accessible: true,
            data: Some("iam/role".to_string()),
            risk: "CRITICAL".to_string(),
        };
        let json = serde_json::to_string_pretty(&f).unwrap();
        assert!(json.contains("CRITICAL"));
    }

    #[test]
    fn test_metadata_finding_inaccessible() {
        let f = MetadataFinding {
            endpoint: "GCP".to_string(),
            accessible: false,
            data: None,
            risk: "NONE".to_string(),
        };
        assert!(!f.accessible);
        assert!(f.data.is_none());
    }

    #[test]
    fn test_check_aws_accessibility() {
        let result = CloudMetadataApi::check_aws();
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.source, "AWS IMDS");
        assert!(!resp.accessible);
    }

    #[test]
    fn test_check_gcp_accessibility() {
        let result = CloudMetadataApi::check_gcp();
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.source, "GCP Metadata");
        assert!(!resp.accessible);
    }

    #[test]
    fn test_check_azure_accessibility() {
        let result = CloudMetadataApi::check_azure();
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.source, "Azure IMDS");
        assert!(!resp.accessible);
    }

    #[test]
    fn test_scan_all_returns_three() {
        let findings = CloudMetadataApi::scan_all();
        assert_eq!(findings.len(), 3);
        let endpoints: Vec<&str> = findings.iter().map(|f| f.endpoint.as_str()).collect();
        assert!(endpoints.iter().any(|e| e.contains("AWS")));
        assert!(endpoints.iter().any(|e| e.contains("GCP")));
        assert!(endpoints.iter().any(|e| e.contains("Azure")));
    }

    #[test]
    fn test_scan_all_none_accessible() {
        let findings = CloudMetadataApi::scan_all();
        for f in &findings {
            assert!(!f.accessible);
        }
    }

    #[test]
    fn test_check_ssrf_with_ip() {
        let result = CloudMetadataApi::check_ssrf_vulnerability("http://10.0.0.1/admin");
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_ssrf_with_localhost() {
        let result = CloudMetadataApi::check_ssrf_vulnerability("http://localhost:8080/api");
        assert!(result.is_ok());
    }

    #[test]
    fn test_metadata_risk_levels() {
        let risks = vec!["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
        for risk in risks {
            let f = MetadataFinding {
                endpoint: "test".to_string(),
                accessible: false,
                data: None,
                risk: risk.to_string(),
            };
            let json = serde_json::to_string(&f).unwrap();
            assert!(json.contains(risk));
        }
    }

    #[test]
    fn test_metadata_finding_serialized_keys() {
        let f = MetadataFinding {
            endpoint: "AWS".to_string(),
            accessible: true,
            data: Some("secret".to_string()),
            risk: "HIGH".to_string(),
        };
        let json = serde_json::to_string_pretty(&f).unwrap();
        assert!(json.contains("\"endpoint\""));
        assert!(json.contains("\"accessible\""));
        assert!(json.contains("\"data\""));
        assert!(json.contains("\"risk\""));
    }

    #[test]
    fn test_cloud_metadata_api_url_constants() {
        let aws = "http://169.254.169.254/latest/meta-data/";
        let gcp = "http://metadata.google.internal/computeMetadata/v1/";
        let azure = "http://169.254.169.254/metadata/instance";
        assert!(aws.contains("169.254.169.254"));
        assert!(gcp.contains("metadata.google.internal"));
        assert!(azure.contains("169.254.169.254"));
    }
}
