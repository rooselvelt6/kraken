use chrono::Utc;
use regex::Regex;
use scraper::{Html, Selector};

use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

#[derive(Debug, Clone)]
pub struct DataCollector;

impl DataCollector {
    pub fn extract_all(text: &str, source_url: Option<&str>) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        findings.extend(Self::extract_emails(text, source_url));
        findings.extend(Self::extract_urls(text, source_url));
        findings.extend(Self::extract_ips(text, source_url));
        findings.extend(Self::extract_phones(text, source_url));
        findings
    }

    pub fn extract_from_html(html: &str, source_url: Option<&str>) -> Vec<OsintFinding> {
        let mut findings = Self::extract_all(html, source_url);
        let document = Html::parse_document(html);

        if let Ok(selector) = Selector::parse("a[href]") {
            for element in document.select(&selector) {
                if let Some(href) = element.value().attr("href") {
                    let href = href.trim();
                    if href.starts_with("mailto:") {
                        let email = href.trim_start_matches("mailto:").trim();
                        if !email.is_empty() && email.contains('@') {
                            findings.push(OsintFinding {
                                source: OsintSource {
                                    name: "html".into(),
                                    reliability: Reliability::High,
                                    url: source_url.map(String::from),
                                },
                                kind: FindingKind::Email,
                                value: email.to_string(),
                                context: None,
                                confidence: 0.95,
                                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    pub fn extract_emails(text: &str, source_url: Option<&str>) -> Vec<OsintFinding> {
        let re = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for cap in re.find_iter(text) {
            let email = cap.as_str().to_lowercase();
            if seen.insert(email.clone()) {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "regex/extract_emails".into(),
                        reliability: Reliability::High,
                        url: source_url.map(String::from),
                    },
                    kind: FindingKind::Email,
                    value: email,
                    context: None,
                    confidence: 0.9,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }
        findings
    }

    pub fn extract_urls(text: &str, source_url: Option<&str>) -> Vec<OsintFinding> {
        let re = Regex::new(
            r"\bhttps?://[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})(?:/[A-Za-z0-9%._~:/?#\[\]@!$&'()*+,;=-]*)?"
        ).unwrap();
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for cap in re.find_iter(text) {
            let url = cap.as_str().to_string();
            if seen.insert(url.clone()) {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "regex/extract_urls".into(),
                        reliability: Reliability::High,
                        url: source_url.map(String::from),
                    },
                    kind: FindingKind::Url,
                    value: url,
                    context: None,
                    confidence: 0.9,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }
        findings
    }

    pub fn extract_ips(text: &str, source_url: Option<&str>) -> Vec<OsintFinding> {
        let re = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for cap in re.find_iter(text) {
            let ip = cap.as_str().to_string();
            if seen.insert(ip.clone()) {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "regex/extract_ips".into(),
                        reliability: Reliability::High,
                        url: source_url.map(String::from),
                    },
                    kind: FindingKind::IpAddress,
                    value: ip,
                    context: None,
                    confidence: 0.95,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }
        findings
    }

    pub fn extract_phones(text: &str, source_url: Option<&str>) -> Vec<OsintFinding> {
        let re = Regex::new(
            r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,4}\b"
        ).unwrap();
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for cap in re.find_iter(text) {
            let phone = cap.as_str().to_string();
            if seen.insert(phone.clone()) {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "regex/extract_phones".into(),
                        reliability: Reliability::Medium,
                        url: source_url.map(String::from),
                    },
                    kind: FindingKind::PhoneNumber,
                    value: phone,
                    context: None,
                    confidence: 0.7,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_emails_from_text() {
        let text = "Contact support@example.com or admin@test.org for help.";
        let findings = DataCollector::extract_emails(text, None);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.value == "support@example.com"));
        assert!(findings.iter().any(|f| f.value == "admin@test.org"));
    }

    #[test]
    fn extracts_urls_from_text() {
        let text = "Visit https://example.com/path?q=1 and http://test.org.";
        let findings = DataCollector::extract_urls(text, None);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn extracts_ips_from_text() {
        let text = "Server at 192.168.1.1 and 10.0.0.1";
        let findings = DataCollector::extract_ips(text, None);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn extracts_phones_from_text() {
        let text = "Call +1-555-123-4567 or (212) 555 7890";
        let findings = DataCollector::extract_phones(text, None);
        assert!(findings.len() >= 2);
    }

    #[test]
    fn extract_all_returns_deduplicated_findings() {
        let text = "Email: test@example.com, site: https://example.com, IP: 10.0.0.1";
        let findings = DataCollector::extract_all(text, None);
        assert!(findings.len() >= 3);
        assert!(findings.iter().any(|f| f.value == "test@example.com"));
        assert!(findings.iter().any(|f| f.value == "https://example.com"));
        assert!(findings.iter().any(|f| f.value == "10.0.0.1"));
    }

    #[test]
    fn extract_html_mailto_links() {
        let html = r#"<a href="mailto:user@example.com">Email</a>"#;
        let findings = DataCollector::extract_from_html(html, None);
        assert!(findings.iter().any(|f| f.value == "user@example.com"));
    }

    #[test]
    fn deduplicates_emails() {
        let text = "a@b.com a@b.com a@b.com";
        let findings = DataCollector::extract_emails(text, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn extracts_emails_case_insensitive() {
        let text = "User@Example.COM and USER@EXAMPLE.COM";
        let findings = DataCollector::extract_emails(text, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn extracts_ip_with_source_url() {
        let text = "Server at 10.0.0.1";
        let findings = DataCollector::extract_ips(text, Some("https://example.com"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].source.url.is_some());
    }

    #[test]
    fn extract_urls_no_matches() {
        let text = "No URLs here, just plain text.";
        let findings = DataCollector::extract_urls(text, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_emails_no_matches() {
        let text = "No emails here.";
        let findings = DataCollector::extract_emails(text, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_ips_no_matches() {
        let text = "No IPs here.";
        let findings = DataCollector::extract_ips(text, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_phones_no_matches() {
        let text = "No phones here.";
        let findings = DataCollector::extract_phones(text, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_from_html_no_mailto() {
        let html = r#"<a href="https://example.com">Link</a>"#;
        let findings = DataCollector::extract_from_html(html, None);
        assert!(!findings.iter().any(|f| f.kind == FindingKind::Email));
    }

    #[test]
    fn deduplicates_urls() {
        let text = "Visit https://example.com and again https://example.com";
        let findings = DataCollector::extract_urls(text, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn deduplicates_ips() {
        let text = "10.0.0.1 and 10.0.0.1 again";
        let findings = DataCollector::extract_ips(text, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn extract_all_empty_text() {
        let findings = DataCollector::extract_all("", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_html_mailto_with_params() {
        let html = r#"<a href="mailto:user@example.com?subject=hello">Email</a>"#;
        let findings = DataCollector::extract_from_html(html, None);
        assert!(findings.iter().any(|f| f.value.contains("user@example.com")));
    }
}
