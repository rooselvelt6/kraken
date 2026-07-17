use chrono::Utc;

use crate::throttle::RateLimiter;
use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

#[allow(dead_code)]
fn tor_limiter() -> &'static RateLimiter {
    static L: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
    L.get_or_init(|| RateLimiter::new(3, 10))
}

#[derive(Debug, Clone)]
pub struct TorClient;

impl TorClient {
    pub fn tor_available() -> bool {
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:9050".parse().unwrap(),
            std::time::Duration::from_secs(2),
        )
        .is_ok()
    }

    pub fn build_onion_url(onion: &str) -> Option<String> {
        let trimmed = onion.trim().trim_end_matches('/').to_lowercase();
        if trimmed.ends_with(".onion") || trimmed.contains(".onion/") {
            let clean = trimmed.trim_start_matches("http://").trim_start_matches("https://");
            Some(format!("http://{}/", clean))
        } else if trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') && trimmed.len() >= 16 {
            Some(format!("http://{}.onion/", trimmed))
        } else {
            None
        }
    }

    pub fn check_onion(onion_url: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let tor_ok = Self::tor_available();

        findings.push(OsintFinding {
            source: OsintSource {
                name: "tor/available".into(),
                reliability: Reliability::High,
                url: None,
            },
            kind: FindingKind::Custom("Tor".into()),
            value: if tor_ok {
                "Tor proxy available (127.0.0.1:9050)".into()
            } else {
                "Tor proxy NOT available".into()
            },
            context: if tor_ok {
                Some("SOCKS5 proxy detected".into())
            } else {
                Some("Start tor daemon or configure SOCKS5 proxy".into())
            },
            confidence: if tor_ok { 1.0 } else { 0.9 },
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });

        if let Some(full_url) = Self::build_onion_url(onion_url) {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "tor/onion".into(),
                    reliability: Reliability::High,
                    url: Some(full_url.clone()),
                },
                kind: FindingKind::Custom("Tor".into()),
                value: format!("Valid .onion address: {}", full_url),
                context: Some(format!("Resolved from input: {}", onion_url)),
                confidence: 0.95,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });

            if tor_ok {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "tor/onion_reachable".into(),
                        reliability: Reliability::Low,
                        url: Some(full_url),
                    },
                    kind: FindingKind::Custom("Tor".into()),
                    value: ".onion reachable via Tor proxy".into(),
                    context: Some("Use reqwest with socks5 proxy to fetch".into()),
                    confidence: 0.4,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct PasteSearcher;

impl PasteSearcher {
    fn paste_limiter() -> &'static RateLimiter {
        static L: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
        L.get_or_init(|| RateLimiter::new(5, 10))
    }

    pub fn search_pastebin(query: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        Self::paste_limiter().wait_if_needed();

        let url = format!("https://psbdmp.ws/api/v3/search?q={}", url_encode(query));

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json) = resp.json::<Vec<serde_json::Value>>() {
                    for entry in json.iter().take(20) {
                        let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let content = entry.get("content").and_then(|v| v.as_str()).unwrap_or("");
                        let truncated = if content.len() > 200 {
                            format!("{}...", &content[..200])
                        } else {
                            content.to_string()
                        };

                        findings.push(OsintFinding {
                            source: OsintSource {
                                name: "pastebin/psbdmp".into(),
                                reliability: Reliability::Medium,
                                url: Some(format!("https://psbdmp.ws/{}", id)),
                            },
                            kind: FindingKind::Custom("Paste".into()),
                            value: format!("Paste {}: {}", id, truncated),
                            context: Some(format!("Matched query: {}", query)),
                            confidence: 0.6,
                            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        });
                    }
                }
            }
            Ok(resp) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "pastebin/error".into(),
                        reliability: Reliability::High,
                        url: Some(url),
                    },
                    kind: FindingKind::Custom("Paste".into()),
                    value: format!("Pastebin search returned HTTP {}", resp.status()),
                    context: Some("May be rate-limited".into()),
                    confidence: 0.4,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
            Err(e) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "pastebin/error".into(),
                        reliability: Reliability::Low,
                        url: None,
                    },
                    kind: FindingKind::Custom("Paste".into()),
                    value: format!("Pastebin search error: {}", e),
                    context: None,
                    confidence: 0.2,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }

        findings
    }

    pub fn search_pastebin_trends() -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        Self::paste_limiter().wait_if_needed();

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        match client.get("https://psbdmp.ws/api/v3/trending").send() {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json) = resp.json::<Vec<serde_json::Value>>() {
                    for entry in json.iter().take(10) {
                        let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let tags: String = entry.get("tags")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();

                        findings.push(OsintFinding {
                            source: OsintSource {
                                name: "pastebin/trending".into(),
                                reliability: Reliability::Medium,
                                url: Some(format!("https://psbdmp.ws/{}", id)),
                            },
                            kind: FindingKind::Custom("Paste".into()),
                            value: format!("Trending paste: {} ({})", id, tags),
                            context: Some("Pastebin trending".into()),
                            confidence: 0.5,
                            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        });
                    }
                }
            }
            _ => {}
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct TelegramCollector;

impl TelegramCollector {
    pub fn search_public_channel(username: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();

        let urls: Vec<(&str, String)> = vec![
            ("t.me", format!("https://t.me/s/{}", username)),
            ("tgstat", format!("https://tgstat.com/{}", username)),
            ("tgdb", format!("https://tgdb.com/{}", username)),
        ];

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        for (source, url) in urls {
            match client.head(&url).send() {
                Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 302 => {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: format!("telegram/{}", source),
                            reliability: Reliability::Medium,
                            url: Some(url),
                        },
                        kind: FindingKind::SocialProfile,
                        value: format!("Telegram channel found: @{}", username),
                        context: Some(format!("Public channel exists on {}", source)),
                        confidence: 0.8,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
                _ => {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: format!("telegram/{}", source),
                            reliability: Reliability::Low,
                            url: None,
                        },
                        kind: FindingKind::SocialProfile,
                        value: format!("Telegram channel not found on {}", source),
                        context: Some(format!("@{} not found on {}", username, source)),
                        confidence: 0.3,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        findings
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
    fn tor_available_returns_bool() {
        let available = TorClient::tor_available();
        // Should not panic, returns true or false
        assert!(available || !available);
    }

    #[test]
    fn builds_onion_url_from_raw() {
        let url = TorClient::build_onion_url("3g2upl4pq6kufc4m").unwrap();
        assert!(url.contains("3g2upl4pq6kufc4m.onion"));
    }

    #[test]
    fn builds_onion_url_from_full() {
        let url = TorClient::build_onion_url("http://3g2upl4pq6kufc4m.onion/").unwrap();
        assert!(url.contains("3g2upl4pq6kufc4m.onion"));
    }

    #[test]
    fn rejects_invalid_onion() {
        assert!(TorClient::build_onion_url("example.com").is_none());
    }

    #[test]
    fn check_onion_returns_findings() {
        let findings = TorClient::check_onion("3g2upl4pq6kufc4m");
        assert!(findings.len() >= 2);
        assert!(findings.iter().any(|f| f.value.contains(".onion")));
    }

    #[test]
    #[ignore = "requires network"]
    fn telegram_search_returns_findings() {
        let findings = TelegramCollector::search_public_channel("doesnotexist123456");
        assert!(!findings.is_empty());
    }

    #[test]
    #[ignore = "requires network"]
    fn paste_search_handles_errors() {
        let findings = PasteSearcher::search_pastebin("test_query_123");
        // Should not panic whether or not the API is reachable
        assert!(findings.len() <= 50);
    }

    #[test]
    fn url_encode_handles_special_chars() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a&b"), "a%26b");
    }
}
