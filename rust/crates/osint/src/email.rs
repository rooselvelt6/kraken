use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachEntry {
    pub service: String,
    pub breach_date: Option<String>,
    pub data_classes: Vec<String>,
    pub source: String,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct EmailEnricher;

impl EmailEnricher {
    pub fn validate_format(email: &str) -> bool {
        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts.len() != 2 {
            return false;
        }
        let local = parts[1];
        let domain = parts[0];

        if local.is_empty() || domain.is_empty() {
            return false;
        }

        if !domain.contains('.') || domain.ends_with('.') {
            return false;
        }

        true
    }

    pub fn extract_domain(email: &str) -> Option<String> {
        let mut parts = email.rsplitn(2, '@');
        let domain = parts.next()?;
        parts.next()?; // ensure there was a '@' separator
        if domain.is_empty() { None } else { Some(domain.to_lowercase()) }
    }

    pub fn enrich(email: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let lower = email.to_lowercase().trim().to_string();

        if !Self::validate_format(&lower) {
            return findings;
        }

        findings.push(OsintFinding {
            source: OsintSource {
                name: "email/format".into(),
                reliability: Reliability::High,
                url: None,
            },
            kind: FindingKind::Email,
            value: lower.clone(),
            context: Some("Email validated (format check passed)".into()),
            confidence: 1.0,
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });

        if let Some(domain) = Self::extract_domain(&lower) {
            if let Some(mx_domains) = Self::check_mx(&domain) {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "email/mx".into(),
                        reliability: Reliability::High,
                        url: None,
                    },
                    kind: FindingKind::Custom("MX_Records".into()),
                    value: format!("Domain {} has {} MX record(s)", domain, mx_domains.len()),
                    context: Some(format!("MX servers: {}", mx_domains.join(", "))),
                    confidence: 0.95,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            } else {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "email/mx".into(),
                        reliability: Reliability::High,
                        url: None,
                    },
                    kind: FindingKind::Custom("MX_Records".into()),
                    value: format!("Domain {} has no MX records", domain),
                    context: Some("Domain may not accept email".into()),
                    confidence: 0.7,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }

            let domain_lower = domain.to_lowercase();
            let common_providers = [
                ("gmail.com", "Google Gmail"),
                ("yahoo.com", "Yahoo Mail"),
                ("outlook.com", "Microsoft Outlook"),
                ("hotmail.com", "Microsoft Hotmail"),
                ("protonmail.com", "ProtonMail"),
                ("proton.me", "ProtonMail"),
                ("icloud.com", "Apple iCloud"),
                ("me.com", "Apple iCloud"),
                ("aol.com", "AOL Mail"),
                ("mail.com", "Mail.com"),
                ("zoho.com", "Zoho Mail"),
                ("yandex.com", "Yandex Mail"),
                ("gmx.com", "GMX Mail"),
                ("tutanota.com", "Tutanota"),
                ("fastmail.com", "Fastmail"),
            ];

            for (provider_domain, provider_name) in &common_providers {
                if domain_lower == *provider_domain || domain_lower.ends_with(&format!(".{}", provider_domain)) {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: "email/provider".into(),
                            reliability: Reliability::High,
                            url: None,
                        },
                        kind: FindingKind::Custom("EmailProvider".into()),
                        value: format!("Email provider: {}", provider_name),
                        context: Some(format!("Domain {} belongs to {}", domain, provider_name)),
                        confidence: 0.95,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                    break;
                }
            }
        }

        findings
    }

    fn check_mx(domain: &str) -> Option<Vec<String>> {
        use hickory_resolver::proto::rr::RData;
        use hickory_resolver::TokioResolver;
        let rt = tokio::runtime::Runtime::new().ok()?;
        rt.block_on(async {
            let resolver = TokioResolver::builder_tokio().ok()?.build().ok()?;
            let response = resolver.mx_lookup(domain).await.ok()?;
            let mx: Vec<String> = response.answers().iter()
                .filter_map(|r| match &r.data {
                    RData::MX(mx) => Some(mx.exchange.to_string()),
                    _ => None,
                })
                .collect();
            Some(mx)
        })
    }

    pub fn check_breaches(email: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();

        let url = format!("https://haveibeenpwned.com/account/{}", email);

        findings.push(OsintFinding {
            source: OsintSource {
                name: "hibp/url".into(),
                reliability: Reliability::Low,
                url: Some(url),
            },
            kind: FindingKind::BreachData,
            value: format!("Breach report for {}", email),
            context: Some("Visit the HIBP URL for breach details. API requires HIBP_API_KEY.".into()),
            confidence: 0.3,
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });

        if let Some(api_key) = std::env::var("HIBP_API_KEY").ok() {
            if let Ok(breaches) = Self::hibp_api_request(email, &api_key) {
                for breach in breaches {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: "hibp/api".into(),
                            reliability: Reliability::High,
                            url: Some(format!("https://haveibeenpwned.com/breach/{}", breach.service)),
                        },
                        kind: FindingKind::BreachData,
                        value: format!("Breach: {} - {}", breach.service, breach.breach_date.unwrap_or_default()),
                        context: Some(format!("Data classes: {}", breach.data_classes.join(", "))),
                        confidence: 0.95,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        findings
    }

    fn hibp_api_request(email: &str, api_key: &str) -> Result<Vec<BreachEntry>, String> {
        let encoded = url_encode(&email.to_lowercase());
        let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false", encoded);

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client
            .get(&url)
            .header("hibp-api-key", api_key)
            .header("user-agent", "Kraken-OSINT/1.0")
            .send()
            .map_err(|e| format!("HIBP request: {e}"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(vec![]);
        }

        if !resp.status().is_success() {
            return Err(format!("HIBP returned HTTP {}", resp.status()));
        }

        let raw: Vec<serde_json::Value> = resp.json().map_err(|e| format!("HIBP parse: {e}"))?;
        let breaches = raw.into_iter().map(|v| BreachEntry {
            service: v.get("Name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string(),
            breach_date: v.get("BreachDate").and_then(|d| d.as_str()).map(String::from),
            data_classes: v.get("DataClasses").and_then(|d| d.as_array())
                .map(|arr| arr.iter().filter_map(|c| c.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            source: "HaveIBeenPwned".into(),
            confidence: 0.95,
        }).collect();

        Ok(breaches)
    }
}

fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => result.push(byte as char),
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_correct_email() {
        assert!(EmailEnricher::validate_format("user@example.com"));
        assert!(EmailEnricher::validate_format("test.user@sub.example.co.uk"));
    }

    #[test]
    fn rejects_invalid_email() {
        assert!(!EmailEnricher::validate_format("not-an-email"));
        assert!(!EmailEnricher::validate_format("user@"));
        assert!(!EmailEnricher::validate_format("@domain"));
        assert!(!EmailEnricher::validate_format(""));
    }

    #[test]
    fn extracts_domain() {
        assert_eq!(EmailEnricher::extract_domain("user@Example.COM"), Some("example.com".into()));
        assert_eq!(EmailEnricher::extract_domain("no-at"), None);
    }

    #[test]
    fn detects_gmail_provider() {
        let findings = EmailEnricher::enrich("user@gmail.com");
        assert!(findings.iter().any(|f| f.value.contains("Gmail")));
    }

    #[test]
    fn enriches_email_with_mx_check() {
        let findings = EmailEnricher::enrich("test@example.org");
        let mx_findings: Vec<_> = findings.iter().filter(|f| f.source.name == "email/mx").collect();
        assert!(!mx_findings.is_empty(), "should have MX findings");
    }

    #[test]
    fn sha2_generates_hash() {
        use sha2::Digest;
        let hash = format!("{:x}", sha2::Sha256::digest(b"test@example.com"));
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn breach_check_returns_hibp_url() {
        let findings = EmailEnricher::check_breaches("test@example.com");
        assert!(findings.iter().any(|f| f.source.name == "hibp/url"));
    }
}
